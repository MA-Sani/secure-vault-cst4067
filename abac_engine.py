"""
abac_engine.py
Custom Attribute-Based Access Control (ABAC) Policy Engine.

How it works:
  1. Takes user_uid, file_id, and the requested action (read/write/delete).
  2. Fetches the user's attributes from Firestore (department, clearance_level, etc.).
  3. Fetches the policy attached to the file from Firestore.
  4. Evaluates every condition in the policy against the user's attributes.
  5. Returns (allowed: bool, reason: str).

This is more powerful than standard RBAC because policies can combine
multiple attribute conditions with operators (equals, gte, lte, in_list, etc.)
without hardcoding roles.

Example policy stored in Firestore:
  {
    policy_name: "Finance Read (Clearance 2+)",
    conditions: [
      { attribute: "department", operator: "equals", value: "Finance" },
      { attribute: "clearance_level", operator: "gte", value: 2 }
    ],
    permitted_actions: ["read"]
  }
"""


class ABACEngine:

    SUPPORTED_OPERATORS = ('equals', 'not_equals', 'gte', 'lte', 'in_list')

    def __init__(self, db):
        """
        db: a google.cloud.firestore.Client instance
        """
        self.db = db

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────

    def evaluate(self, user_uid: str, file_id: str, action: str) -> tuple[bool, str]:
        """
        Evaluate whether user_uid may perform action on file_id.
        Returns (True, reason) or (False, reason).
        """
        # 1. Load user attributes
        user_attrs, user_err = self._get_user_attrs(user_uid)
        if user_err:
            return False, user_err

        # 2. Load file metadata
        file_data, file_err = self._get_file_data(file_id)
        if file_err:
            return False, file_err

        # 3. Owner always has read access to their own files
        if file_data.get('owner_uid') == user_uid and action == 'read':
            return True, 'Owner access'

        # 4. No policy attached — only owner can act on it
        policy_id = file_data.get('policy_id', '').strip()
        if not policy_id:
            if file_data.get('owner_uid') == user_uid:
                return True, 'Owner access (no policy)'
            return False, 'No policy assigned and requester is not the owner'

        # 5. Load the policy
        policy, policy_err = self._get_policy(policy_id)
        if policy_err:
            return False, policy_err

        # 6. Check that the requested action is in the policy's permitted actions
        if action not in policy.get('permitted_actions', []):
            return False, f"Action '{action}' is not permitted by policy '{policy_id}'"

        # 7. Evaluate every condition
        conditions = policy.get('conditions', [])
        if not conditions:
            # Empty conditions = open to all authenticated users (public policy)
            return True, f"Policy '{policy_id}' — no conditions (public access)"

        for condition in conditions:
            passed, fail_reason = self._check_condition(condition, user_attrs)
            if not passed:
                return False, f"Condition failed: {fail_reason}"

        return True, f"All {len(conditions)} condition(s) met for policy '{policy_id}'"

    # ──────────────────────────────────────────────
    # Condition evaluation
    # ──────────────────────────────────────────────

    def _check_condition(self, condition: dict, user_attrs: dict) -> tuple[bool, str]:
        """
        Evaluate a single condition dict against user_attrs.
        Returns (passed, fail_reason).
        """
        attr = condition.get('attribute', '')
        operator = condition.get('operator', '')
        required = condition.get('value')

        if operator not in self.SUPPORTED_OPERATORS:
            return False, f"Unknown operator '{operator}'"

        user_val = user_attrs.get(attr)

        if user_val is None:
            return False, f"User has no attribute '{attr}'"

        if operator == 'equals':
            result = str(user_val).strip().lower() == str(required).strip().lower()
            reason = f"{attr}={user_val} must equal {required}"

        elif operator == 'not_equals':
            result = str(user_val).strip().lower() != str(required).strip().lower()
            reason = f"{attr}={user_val} must not equal {required}"

        elif operator == 'gte':
            try:
                result = float(user_val) >= float(required)
                reason = f"{attr}={user_val} must be >= {required}"
            except (ValueError, TypeError):
                return False, f"Cannot compare {attr}={user_val} >= {required} (not numeric)"

        elif operator == 'lte':
            try:
                result = float(user_val) <= float(required)
                reason = f"{attr}={user_val} must be <= {required}"
            except (ValueError, TypeError):
                return False, f"Cannot compare {attr}={user_val} <= {required} (not numeric)"

        elif operator == 'in_list':
            if not isinstance(required, list):
                required = [required]
            result = str(user_val) in [str(v) for v in required]
            reason = f"{attr}={user_val} must be in {required}"

        else:
            return False, f"Operator '{operator}' not implemented"

        return result, ('' if result else reason)

    # ──────────────────────────────────────────────
    # Firestore helpers
    # ──────────────────────────────────────────────

    def _get_user_attrs(self, uid: str) -> tuple[dict | None, str | None]:
        doc = self.db.collection('users').document(uid).get()
        if not doc.exists:
            return None, f"User '{uid}' not found in Firestore"
        return doc.to_dict(), None

    def _get_file_data(self, file_id: str) -> tuple[dict | None, str | None]:
        doc = self.db.collection('files').document(file_id).get()
        if not doc.exists:
            return None, f"File '{file_id}' not found"
        return doc.to_dict(), None

    def _get_policy(self, policy_id: str) -> tuple[dict | None, str | None]:
        doc = self.db.collection('policies').document(policy_id).get()
        if not doc.exists:
            return None, f"Policy '{policy_id}' not found"
        return doc.to_dict(), None

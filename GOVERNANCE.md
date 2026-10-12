# Governance

Furcate is developed and stewarded by Praecise, in the open, under Apache-2.0.

## How decisions are made

Furcate follows a maintainer model with a steward, in the way several large open-source projects are run: a small group of maintainers reviews and merges changes, and the steward is accountable for direction and for keeping the open base complete.

- **Maintainers** review and merge changes in the areas they maintain. A change needs approval from a maintainer of each area it touches.
- **The steward** (Praecise) appoints the lead maintainer, resolves disagreements maintainers cannot settle, and is accountable for releases and for the security process.
- **Decisions that shape the system** are written down as decision records in `docs/decisions/`, proposed as a pull request, discussed in public, and merged when accepted. A decision record states the context, the decision, and what it rules out. Superseding one takes a new record, never an edit of the old.
- **Interfaces** between parts of the system, and between Furcate and the hardware it runs on, are specified in `docs/interfaces/`. A change to an interface goes through the same review as a decision.

## The open base stays complete

What makes a trust claim (identity, attestation, policy, the ledger, the kill switch) and what a person needs to run their own machines is in this repository and stays here. Production fleet operation is offered separately by Praecise and is never required to run Furcate.

## Becoming a maintainer

Contributors who have made sustained, high-quality contributions to an area are invited to maintain it by the existing maintainers of that area, with the lead maintainer's agreement.

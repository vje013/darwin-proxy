**Problem**
- Zo lets anyone build and run a business on AI, including finance (one-person hedge funds, advisory firms, fintech)
- The moment a finance user puts real client data (names, tax IDs, holdings) through Zo, that data gets sent to third-party AI models (OpenAI, Anthropic, MiniMax, etc.)
- That is a compliance violation under GLBA, Reg S-P, and state privacy laws — the liability lands on the user, and Zo's "private by default" claim becomes deceptive
- Without a fix, Zo's highest-value users (regulated finance) can't use the product on real data

**What Darwin Proxy Does**
- Strips identity from sensitive records while preserving the analytical signal they carry
- Names are gender-matched (John → Mark, not John → Danielle)
- Locations stay in-region (Connecticut → Vermont, both Northeast)
- Format-only fields (tax IDs, phone numbers) get structurally valid fakes
- The same real entity always maps to the same fake entity across the entire dataset (consistency map)
- Signal-bearing fields (share class, shares owned, acquisition date) are untouched — the data stays usable for AI

**Architecture**
- Input: raw CSV/record with PII
- Detector: identifies and types every sensitive span (name, email, city, phone, EIN)
- Partitioner: separates identity fields (abstract these) from environment/signal fields (keep these)
- Semantic classifier: characterizes each value by its neighborhood (gender, region, cohort) rather than just its type
- Substitutor: draws a concrete replacement from the same semantic neighborhood, not a random fake
- Consistency map: keyed by entity, ensures the same person/place maps to the same replacement everywhere (reversible in round-trip mode, discardable in one-way mode)
- Output: abstracted CSV + SHA-256 before/after hashes

**Workflow**
- Finance user uploads client data to Zo
- Proxy intercepts before data leaves the box to any third-party model
- Identity is stripped, signal is preserved, replacements are semantically faithful
- The AI model receives usable data with zero real PII
- The user gets AI-powered analysis on their real dataset without ever exposing a real client

**What's Next (full product roadmap)**
- Signed Ed25519 attestation certificate proving exactly how data was abstracted (built on Darwin Agentic Cloud)
- K-anonymity re-identification gate validating that no replacement is too rare to be safe
- Chroma vector-based semantic classifier replacing heuristic matching with embedding-space neighborhoods
- Open-core: engine free (Apache-2.0), policy packs and certification paid

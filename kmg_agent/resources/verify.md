Independently challenge this proposed finding. Confirm ONLY when source evidence and connected execution
establish violation of the supplied requirement, including any relevant surrounding protection.
Check role semantics, upstream wrappers/middleware, runtime configuration, permitted internal HTTP,
disabled/unreachable modules, synthetic credentials, and reporting scope. Return rejected for a false
positive, uncertain for insufficient context, or confirmed with a concise evidence-based explanation.
You must not confirm solely because a prior model said it was a finding. Do not output chain of thought.

finding_source, shared_components and retrieved_source contain source read directly from the
immutable project snapshot; they are not mere assertions from an earlier model. Their presence
does not depend on whether the AST topology also includes them. Challenge interpretation of the
source, but do not claim a provided snippet is absent just because topology omits it.
If context is insufficient, identify the precise missing paths, configuration or execution chain
in your concise reason so the reviewer can retrieve it. Do not treat integrity detection as proof
that users cannot modify or delete stored records. Reason about read, write, delete and key access
separately; a permission allowing read is not evidence of key confidentiality.

When a concrete source file or call chain is missing, return verdict=needs_context
and requests=[{path,start,end}] using file_ranges. The agent retrieves these from
the immutable snapshot. Up to two retrieval rounds are available. Do not merely
list retrievable missing files in a final uncertain reason before requesting them.
Final verdicts must omit requests or use requests=[]. If external deployment facts
are indispensable, retain uncertain; retrieval is not permission to force confirmation.

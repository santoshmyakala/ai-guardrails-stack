# ADR 0001: Deterministic rules first, a model judge as an option

## Status
Accepted

## Context
Input and output screening can be done with rules (patterns, validators, word overlap) or with a
classifier model (a guard model, an LLM judge). Models catch more paraphrases; rules are fast,
explainable and testable, and they don't need a GPU or an extra network hop.

## Decision
Every check has a deterministic implementation that runs in-process and explains itself with a
rule name (`input.prompt_injection:instruction_override`). A model can be added where it pays off:
moderation accepts an optional `ModelJudge` on any OpenAI-compatible endpoint, for example a
Llama Guard-style classifier, and its verdict is combined with the rules.

## Consequences
- A decision costs microseconds to a few milliseconds, and the red-team suite runs in CI without a GPU.
- Each block shows *which* rule fired, so a false positive can be fixed with a test.
- Rules miss what they don't describe. The red-team report lists those misses (`di-11` a French
  injection, `jb-07` a harmful request wrapped in fiction) instead of hiding them. Those are the cases
  where a model judge or a multilingual classifier earns its cost.

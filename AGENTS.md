# agent.md (AI-first; shared by both members)

[context]
project=CryptoLab (LTHDT final: AES, RSA, ECC, digital signature); stack=C#/.NET 8, xUnit; academic code, not production
reply_language=vi; identifiers/branches/commits=en
files: plan.md=tasks+status (source of truth); project_reference.md=design; docs/uml/*.mmd=UML

[identify_user]
read `git config user.name`; Minh Đức => owner D; Quang Chiến => owner C; else ask
user statement overrides git config; remind them to fix git config
first reply states: who, branch, task id

[ownership]  # edit only own paths
D (feature/crypto): src/CryptoLab/Business/Ciphers/, Business/Mathematics/, Domain/CipherType.cs, Services/CipherFactory.cs, matching tests
C (feature/signature): Business/Signing/, Domain/* except CipherType.cs, Infrastructure/, Services/* except CipherFactory.cs, UI/, appsettings.json, matching tests
shared (own PR, both approve): docs/, README.md, .editorconfig, plan.md (non-status fields), agent.md, interface contracts
other owner's path needed => stop, tell user

[workflow]
one PR per task id; title starts with id (e.g. `T14: ...`); PR target=integration; reviewer=other member; never self-merge
before PR: merge latest integration into own branch; dotnet build && dotnet test green
conflict in other owner's file => stop, report
no force-push to main/integration; main <- integration only with both agreeing
no PR mixing both owners' commits
commit author=current user; format feat(scope)|fix|test|docs|chore; small, one idea
never commit data/, bin/, obj/, real keys

[plan_updates]
edit only `status` of rows where owner=you (or owner=B, your part); same PR as the code
status: todo|doing|review|blocked:<reason>|done
done only with passing tests and the related commit
other changes to plan.md => separate PR, both approve

[architecture]
call direction: UI -> Services -> Business -> Domain -> Infrastructure; downward only, may skip layers, never upward
phases talk only via ICipher, ISigner, IKeyRepository, BigIntCalculator
frozen signatures: change only after stop + reason + both agree + own PR + UML update
one responsibility per class; no empty filler classes; interface <= 4 members
fields private; validate args in constructors

[patterns]
only CipherFactory calls `new` on ciphers
CipherBase subclasses override only DoEncrypt/DoDecrypt (Template Method)
SecureMessenger must not reference AuditLogger (event/Observer)
KeyService depends on IKeyRepository only
extensions (ChaCha20Cipher, InMemoryKeyRepository): own PR, add files only, no edits to old code except one registration line

[crypto]
RNG: RandomNumberGenerator only; never System.Random
no ECB; no unpadded RSA outside test vectors; RSA encrypt=OAEP, sign=PSS
ECC encrypt=ECIES; ECDSA k per RFC 6979; never reuse k; curve=P-256, never invent curves
new nonce per encryption; compare secrets with ConstantTimeEquals
private key: never log, never ToString, never commit; Wipe after use; store encrypted

[errors_config]
only the CryptoException tree; low layers throw, UI catches; never swallow
paths relative; config in appsettings.json

[tests]
every business rule QT has >=1 test; include failure paths
self-implemented code cross-checked against .NET built-ins in tests only, never in production code
never delete/skip tests to get green; commit only when build+test green

[docs_sync]
change in class/field/method/relation => update .mmd in same PR
never claim a checklist item done without evidence (test, commit, report page)
never guess deadline, language, or AES self-implement-vs-library; ask# agent.md (AI-first; shared by both members)

[context]
project=CryptoLab (LTHDT final: AES, RSA, ECC, digital signature); stack=C#/.NET 8, xUnit; academic code, not production
reply_language=vi; identifiers/branches/commits=en
files: plan.md=tasks+status (source of truth); project_reference.md=design; docs/uml/*.mmd=UML

[identify_user]
read `git config user.name`; Minh Đức => owner D; Quang Chiến => owner C; else ask
user statement overrides git config; remind them to fix git config
first reply states: who, branch, task id

[ownership]  # edit only own paths
D (feature/crypto): src/CryptoLab/Business/Ciphers/, Business/Mathematics/, Domain/CipherType.cs, Services/CipherFactory.cs, matching tests
C (feature/signature): Business/Signing/, Domain/* except CipherType.cs, Infrastructure/, Services/* except CipherFactory.cs, UI/, appsettings.json, matching tests
shared (own PR, both approve): docs/, README.md, .editorconfig, plan.md (non-status fields), agent.md, interface contracts
other owner's path needed => stop, tell user

[workflow]
one PR per task id; title starts with id (e.g. `T14: ...`); PR target=integration; reviewer=other member; never self-merge
before PR: merge latest integration into own branch; dotnet build && dotnet test green
conflict in other owner's file => stop, report
no force-push to main/integration; main <- integration only with both agreeing
no PR mixing both owners' commits
commit author=current user; format feat(scope)|fix|test|docs|chore; small, one idea
never commit data/, bin/, obj/, real keys

[plan_updates]
edit only `status` of rows where owner=you (or owner=B, your part); same PR as the code
status: todo|doing|review|blocked:<reason>|done
done only with passing tests and the related commit
other changes to plan.md => separate PR, both approve

[architecture]
call direction: UI -> Services -> Business -> Domain -> Infrastructure; downward only, may skip layers, never upward
phases talk only via ICipher, ISigner, IKeyRepository, BigIntCalculator
frozen signatures: change only after stop + reason + both agree + own PR + UML update
one responsibility per class; no empty filler classes; interface <= 4 members
fields private; validate args in constructors

[patterns]
only CipherFactory calls `new` on ciphers
CipherBase subclasses override only DoEncrypt/DoDecrypt (Template Method)
SecureMessenger must not reference AuditLogger (event/Observer)
KeyService depends on IKeyRepository only
extensions (ChaCha20Cipher, InMemoryKeyRepository): own PR, add files only, no edits to old code except one registration line

[crypto]
RNG: RandomNumberGenerator only; never System.Random
no ECB; no unpadded RSA outside test vectors; RSA encrypt=OAEP, sign=PSS
ECC encrypt=ECIES; ECDSA k per RFC 6979; never reuse k; curve=P-256, never invent curves
new nonce per encryption; compare secrets with ConstantTimeEquals
private key: never log, never ToString, never commit; Wipe after use; store encrypted

[errors_config]
only the CryptoException tree; low layers throw, UI catches; never swallow
paths relative; config in appsettings.json

[tests]
every business rule QT has >=1 test; include failure paths
self-implemented code cross-checked against .NET built-ins in tests only, never in production code
never delete/skip tests to get green; commit only when build+test green

[docs_sync]
change in class/field/method/relation => update .mmd in same PR
never claim a checklist item done without evidence (test, commit, report page)
never guess deadline, language, or AES self-implement-vs-library; ask
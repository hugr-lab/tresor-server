# Specs

One **lightweight spec per change**: a short, honest document so decisions are written down and
reviewable. Same process as tresor's (`tresor/specs/README.md`).

1. Before (or alongside) a change, create `specs/NNN-slug/spec.md` from `TEMPLATE.md`.
2. A protocol change is specced in tresor first (`website/docs/protocol.md` is normative there), then here.
3. Keep the spec current; `Status: implemented` when it lands; reference it in the commit/PR.
4. Supersede, don't rewrite.

Research lives in the local, gitignored `design/` folder.

## Index

| Spec | Title | Status |
| --- | --- | --- |
| [001](001-architecture/spec.md) | tresor-server - state stores, KEK, material by reference, deployment, phases | accepted |
| [002](002-phase1-azure-mvp/spec.md) | phase 1 - the Azure MVP | implemented |
| [003](003-kubernetes/spec.md) | phase 3 - Kubernetes: the CRD store, ref+k8s, workload identity, the Helm chart | draft |

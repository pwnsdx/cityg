# GUI Material System Roadmap

Status: Accepted design direction

Date: 2026-03-25

## Purpose

This document captures the agreed UI architecture direction for the City-G GUI
as we move toward a more native-feeling desktop shell while preserving GPUI as
the primary application framework.

It exists to answer four questions:

- how City-G should approach macOS 26 Liquid Glass
- how GPUI should remain central to the GUI architecture
- how Windows and Linux should fit into the same design system
- what should be built in app code versus vendored GPUI

This note is intended to be a stable reference for:

- GUI implementation
- vendored GPUI extension work
- cross-platform design reviews
- future native-shell refactors
- release planning for visual redesign work

## Executive Summary

City-G should not attempt to make "Apple Liquid Glass" the direct API contract
of the application.

Instead, City-G should build a semantic material system in GPUI with a single
cross-platform API and multiple platform-specific backends.

The direction is:

- GPUI remains the primary application framework
- the app expresses semantic UI roles such as sidebar, toolbar, inspector, and
  floating control chrome
- vendored GPUI gains first-class material primitives for those roles
- macOS 26 and newer use native-backed implementations where it materially
  improves fidelity
- older macOS versions use `NSVisualEffectView`-backed or GPUI-rendered
  fallbacks
- Windows and Linux use GPUI-rendered approximations that preserve hierarchy
  and behavior, without attempting to clone Apple's design language exactly

The core design rule is:

> The app should target semantic materials, not a platform-specific visual
> brand name.

## Background

City-G already uses GPUI as its GUI framework, and the current native shell
already supports:

- transparent titlebar configuration
- blurred window backgrounds
- custom toolbars and split-view-like layout
- custom text input behavior and native menu integration

Relevant code today includes:

- `crates/cityg-gui/src/native/app_shell.rs`
- `crates/cityg-gui/src/native/render_session.rs`
- `crates/cityg-gui/src/native/render_workspace.rs`
- `crates/cityg-gui/src/native/native_text_input.rs`

Vendored GPUI already provides:

- custom layout and styling primitives
- custom paint/canvas support
- images and SVG rendering
- animation support
- macOS window blur/background support

However, GPUI does not currently expose the new macOS 26 Liquid Glass component
system as first-class elements.

That is the architectural gap this document addresses.

## Problem Statement

We want all of the following at the same time:

1. Preserve GPUI as the dominant UI framework for City-G.
2. Achieve a significantly more native-feeling macOS shell.
3. Support Windows and Linux without forking the app design into three
   unrelated codepaths.
4. Avoid turning app code into platform-specific conditionals and native-view
   plumbing.
5. Keep the design system maintainable as GPUI and operating systems evolve.

These goals are in tension because the new macOS 26 design system is not just a
visual style. It includes platform-owned component behavior such as:

- adaptive glass materials
- background extension behavior
- scroll-edge effects
- concentric layout behavior near rounded corners
- navigation and accessory behaviors tied to native scrolling and split views

Those are not yet first-class GPUI concepts.

## Goals

The material-system redesign must satisfy these goals:

1. GPUI remains the primary way City-G builds UI structure, state, and
   interaction.
2. App-level UI code describes semantic roles rather than platform APIs.
3. macOS gets the highest-fidelity implementation where the OS offers native
   support.
4. Windows and Linux receive coherent, polished equivalents rather than a weak
   or broken imitation of macOS.
5. The resulting API is stable enough to replace bespoke panel styling across
   the existing GUI.
6. Accessibility behavior remains explicit and testable.
7. Platform-specific implementation details live in vendored GPUI or narrow
   integration layers rather than throughout City-G app code.

## Non-Goals

This direction does not attempt to:

- reproduce Apple Liquid Glass pixel-for-pixel on non-Apple platforms
- make Windows or Linux visually subordinate to macOS
- rebuild every system-native AppKit container as a GPUI clone in one pass
- rewrite the entire City-G GUI before incremental migration is proven
- implement a renderer-level physically accurate glass simulation as the first
  step

## Core Design Decision

### 1. Build a Semantic Material System in GPUI

City-G should introduce a semantic material system whose public API is framed in
terms of interface purpose, not platform branding.

Examples of semantic concepts:

- sidebar/navigation surface
- toolbar or floating control surface
- inspector surface
- overlay or sheet surface
- search field or grouped control chrome
- scroll-edge separation effect
- background extension area

The app should ask for these concepts directly and let GPUI map them to the
best implementation available on the current platform.

### 2. Keep App Code Platform-Agnostic

City-G application code should not directly express:

- `NSGlassEffectView`
- `NSGlassEffectContainerView`
- `NSBackgroundExtensionView`
- `NSVisualEffectView`
- Windows composition materials
- Linux compositor-specific blur protocols

Those are backend concerns.

### 3. Implement Platform-Specific Backends Under One API

The semantic GPUI material system should be implemented with different fidelity
tiers:

- macOS 26+: native-backed Liquid Glass and related system behaviors where
  practical
- older macOS: native blur plus GPUI-painted accent/highlight/shadow fallback
- Windows: GPUI-rendered material surfaces with a Windows-appropriate aesthetic
- Linux: GPUI-rendered material surfaces with conservative fallbacks due to
  compositor variability

### 4. Prefer Native Interop Over Renderer Reimplementation on macOS

Where macOS 26 offers true component behavior, we should prefer native-hosted
or native-bridged implementations over trying to reproduce the system material
purely in GPUI shaders.

Renderer-level recreation is a later option, not the primary plan.

## Rejected Alternatives

### A. Pure AppKit Shell as the Main Architecture

Rejected as the primary direction.

Reason:

- it would reduce GPUI from "application framework" to "custom content island"
- it would force more UI ownership into native macOS code than we want
- it would increase platform divergence

We may still use narrow native hosting for specific material primitives, but
the app architecture should remain GPUI-first.

### B. Apple-Named Material API in App Code

Rejected.

Reason:

- it would make the app's design language platform-branded and less portable
- it would create low-quality abstractions on Windows and Linux
- it would leak backend implementation details into product code

### C. Full Renderer-Level Liquid Glass Recreation as the First Step

Rejected for the first phase.

Reason:

- too expensive
- too hard to validate against native behavior
- high maintenance burden
- would still not produce real system component behavior

## Proposed Public API Shape

The exact Rust API can evolve, but the public model should look roughly like
this:

```rust
enum MaterialRole {
    Sidebar,
    Toolbar,
    Inspector,
    Overlay,
    SearchField,
    ScrollEdge,
    BackgroundExtension,
    GroupedControls,
}

enum MaterialVariant {
    Adaptive,
    Clear,
    OpaqueFallback,
}

enum MaterialEmphasis {
    Low,
    Medium,
    High,
}

struct MaterialStyle {
    role: MaterialRole,
    variant: MaterialVariant,
    emphasis: MaterialEmphasis,
    tinted: bool,
    interactive: bool,
}
```

Possible GPUI elements:

- `material_surface(style, child)`
- `scroll_edge_surface(style, child)`
- `background_extension_surface(style, child)`
- `control_group_surface(style, child)`

The app should compose these like any other GPUI elements.

## Platform Backend Strategy

### macOS 26 and Newer

Target:

- highest fidelity
- use native system material behavior where practical
- preserve macOS-native interactions, hierarchy, and contrast behavior

Backend approach:

- native-backed material views for core navigation/chrome surfaces
- native scroll-edge/background-extension integration where available
- GPUI remains responsible for layout intent, state, and surrounding structure
- GPUI fallback painting still exists for unsupported cases

Use cases that should get priority on macOS:

- sidebar chrome
- toolbar/floating navigation controls
- inspector shell
- search field and grouped control containers
- scroll-edge-aware top/bottom content boundaries

### Older macOS

Target:

- native-feeling visual shell without depending on macOS 26-only APIs

Backend approach:

- `NSVisualEffectView`-style blur where useful
- GPUI-painted borders, highlights, tinting, and shadows
- no attempt to reproduce every Tahoe-specific adaptive behavior

### Windows

Target:

- polished material hierarchy with Windows-appropriate behavior

Backend approach:

- GPUI-rendered material surfaces
- stronger reliance on tint, shadow, border, and translucency
- avoid calling it "Liquid Glass" in product semantics
- preserve the same information architecture and component roles

Windows-specific design direction:

- lean toward a Mica/Acrylic-inspired shell feeling where appropriate
- keep the main content more opaque than the navigation layer
- prioritize readability over translucency

### Linux

Target:

- coherent and stable rendering across compositors

Backend approach:

- GPUI-rendered material surfaces by default
- optional compositor blur integration only if reliability is acceptable
- conservative fallback to opaque or near-opaque surfaces when blur is
  inconsistent

Linux-specific design direction:

- treat blur as optional enhancement, not a dependency
- preserve spacing, hierarchy, and navigation behavior even without blur

## Capability Model

Vendored GPUI should expose platform material capabilities explicitly.

For example:

```rust
struct PlatformMaterialCapabilities {
    native_glass: bool,
    background_extension: bool,
    scroll_edge_effects: bool,
    concentric_layout_regions: bool,
    adaptive_grouped_controls: bool,
}
```

The app should not branch on these capabilities directly in most cases.

Instead:

- GPUI elements should consume capabilities internally
- the app should only branch when product behavior must change, not visual
  fidelity

## Design Principles

### 1. Navigation Layer, Not Content Layer

Material treatment belongs primarily in:

- window chrome
- navigation
- sidebars
- toolbars
- inspectors
- floating control groups

It should not dominate message content, code blocks, or long-form reading
surfaces.

### 2. Preserve Legibility

The center content layer should generally remain more stable and more opaque
than the surrounding chrome.

This is especially important for City-G because the product includes:

- encrypted message streams
- inline code
- status and recovery indicators
- admin/security panels

### 3. Semantic Consistency Across Platforms

The same component role should communicate the same hierarchy everywhere, even
when the exact material implementation differs.

Example:

- a sidebar should read as elevated navigation on all platforms
- the macOS sidebar may be true native glass
- the Windows and Linux sidebars may be tinted translucent surfaces
- the app semantics and layout remain the same

### 4. Constrain Glass to High-Value Surfaces

Do not glass everything.

The more surfaces compete for elevation, the less useful the material hierarchy
becomes.

## City-G Component Mapping

Initial migration targets in the current GUI:

1. Workspace sidebar
2. Chat header / toolbar row
3. Session inspector shell
4. Search and grouped control rows
5. Join sheet shell
6. Scroll-edge boundaries around chat content and inspectors

Components that should remain mostly content-like:

- message timeline body
- code/message attachments
- error boxes and status copy
- large detail bodies in security or activity panels

## Ownership Boundaries

### What Stays in City-G App Code

- view composition
- product-specific layout
- feature state and actions
- content rendering
- semantic material selection
- migration from old custom styling to semantic surfaces

### What Moves Into Vendored GPUI

- material element types
- platform capability detection
- native macOS material hosting/bridging
- platform-specific fallback behavior
- shared material painting logic
- test harness support for material capability fallbacks

## Accessibility Direction

The material system must not be purely decorative.

The implementation must respect system and product accessibility settings,
including at minimum:

- reduced transparency
- increased contrast
- reduced motion
- inactive-window contrast handling

Requirements:

- every material primitive must have an opaque fallback
- motion-enhanced highlights must be optional
- text contrast over adaptive surfaces must be validated explicitly

## Testing Strategy

This redesign needs testing at three levels.

### 1. API-Level Tests

Validate:

- fallback selection by capability
- semantic role to backend mapping
- inactive/active state transitions
- reduced-transparency and contrast handling

### 2. Snapshot or Golden-Image Tests

Validate:

- sidebar, toolbar, and inspector composition
- grouped control chrome
- search field states
- scroll-edge boundaries

### 3. Manual Platform Review

Validate:

- macOS 26 behavior against native expectations
- older macOS fallback quality
- Windows readability and shell coherence
- Linux reliability under blur/no-blur environments

## Rollout Plan

### Phase 1: Semantic API and GPUI Fallback

Build:

- material roles and variants
- GPUI-rendered fallback surfaces
- basic grouped control and sidebar primitives

Outcome:

- City-G begins migrating away from ad hoc panel styling
- all platforms can use the new API immediately

### Phase 2: City-G Adoption

Migrate:

- sidebar
- header/toolbar
- inspector shell
- join shell
- grouped search and control rows

Outcome:

- consistent semantics in product code
- visual cleanup independent of native backend fidelity

### Phase 3: macOS Native Backend

Add:

- native-backed material implementations for macOS 26+
- older-macOS blur-backed compatibility path

Outcome:

- real macOS-native fidelity on supported systems
- no app-level API churn

### Phase 4: Scroll Edge and Background Extension

Add:

- semantic scroll-edge primitives
- background-extension semantics for large media or rich panels

Outcome:

- closer alignment with the new macOS navigation/content separation model

### Phase 5: Refinement and Performance

Improve:

- animation tuning
- accessibility tuning
- fallback quality on Windows/Linux
- visual consistency across active/inactive window states

## Risks

### 1. GPUI Integration Complexity

Risk:

- native-hosted material views may complicate clipping, hit-testing, layering,
  and resize behavior

Mitigation:

- start with a small number of material primitives
- isolate native hosting behind GPUI internals

### 2. Platform Drift

Risk:

- macOS gains fidelity faster than Windows/Linux

Mitigation:

- build the semantic GPUI fallback first
- keep role-based behavior shared across all platforms

### 3. Over-Application of Glass

Risk:

- product becomes visually noisy and less readable

Mitigation:

- reserve material emphasis for navigation and chrome
- keep content surfaces stable and mostly opaque

### 4. Maintenance Cost of Vendored Framework Changes

Risk:

- GPUI upgrades become harder

Mitigation:

- keep the public GPUI API small and semantic
- isolate backend logic behind a narrow module boundary
- document the extension points clearly as they are introduced

## Open Questions

The following questions remain intentionally open:

1. Should native-backed material hosting be a general GPUI facility or only a
   material-specific one?
2. How much of scroll-edge behavior belongs in GPUI versus app composition?
3. Should Windows receive a more platform-native shell treatment in the future
   if GPUI gains better composition support there?
4. Which City-G panels should remain fully content-like rather than becoming
   chrome-like?

## Immediate Next Steps

1. Define the semantic material types in vendored GPUI.
2. Implement a pure-GPUI fallback backend first.
3. Migrate City-G sidebar, header, and inspector to the new API.
4. Add macOS-native backend support after the semantic API is stable.

## Near-Term Execution Backlog

The next implementation work should proceed in this exact order:

1. Stabilize the semantic GPUI API surface.
   - land `MaterialRole`, `MaterialVariant`, `MaterialEmphasis`, and
     `MaterialStyle`
   - keep the first API intentionally small
   - avoid adding macOS-specific names to the public surface

2. Finish the pure-GPUI fallback backend.
   - ensure semantic surfaces render acceptably on macOS, Windows, and Linux
   - define conservative fallback behavior for reduced-transparency and inactive
     windows
   - avoid any native-hosting dependency in this phase

3. Migrate the first City-G shell surfaces.
   - workspace sidebar
   - top chat/header toolbar
   - inspector shell
   - leave/session controls card
   - join sheet shell

4. Add capability-aware testing.
   - API-level tests for semantic defaults and fallback selection
   - visual or snapshot coverage for sidebar/toolbar/inspector shells
   - explicit inactive-window and reduced-transparency cases

5. Split generic GPUI work from City-G app work.
   - move framework-generic GPUI changes out of `cityg`
   - keep product-specific City-G composition changes inside `cityg`
   - define a repeatable sync process from upstream Zed GPUI sources

6. Add the macOS-native backend.
   - introduce native-hosted or native-bridged material surfaces for macOS 26+
   - keep the same semantic GPUI API
   - preserve the pure-GPUI fallback path for older macOS and other platforms

7. Add advanced behaviors only after the above is stable.
   - scroll-edge semantics
   - background-extension semantics
   - grouped control chrome refinement
   - platform-specific polish on Windows and Linux

## Repository Strategy

### Decision

If City-G continues to add framework-level GPUI functionality, GPUI should move
into a separate maintained fork outside the City-G repository.

Recommended target:

- `pwnsdx/gpui`

### Why

The current vendored GPUI copy inside `cityg` is no longer just a pristine
vendor snapshot. Once we add a semantic material system, native hosting, and
cross-platform fallback logic, the fork becomes a real maintained UI framework
variant rather than a passive dependency copy.

Keeping that work only inside `cityg` creates several problems:

- framework changes and product changes are mixed together
- upstream sync becomes harder to reason about
- generic GPUI improvements are harder to reuse elsewhere
- maintenance and review boundaries stay blurry

### Required Constraint

Because upstream GPUI lives inside the Zed monorepo, `pwnsdx/gpui` must keep a
clear mapping to upstream source commits.

That means the fork should not become an unrelated standalone code dump.

It should instead be maintained as:

- a dedicated fork with imported upstream provenance
- a documented sync process from upstream Zed commits
- a narrow patch stack for custom additions

### Recommended Split Boundary

Move to `pwnsdx/gpui`:

- semantic material primitives
- platform material capability detection
- native material hosting/bridging
- GPUI fallback rendering for semantic materials
- GPUI tests for those framework features

Keep in `cityg`:

- product-specific shell composition
- City-G panel hierarchy
- City-G state/actions
- product-specific color decisions and tuning
- all app-level migration work

### Migration Plan for the Fork

1. Create `pwnsdx/gpui`.
2. Import the current vendored GPUI code with preserved history where possible.
3. Tag the starting point with the upstream source commit it corresponds to.
4. Move framework-generic City-G additions into that fork.
5. Keep City-G consuming GPUI through a path or git dependency during the
   transition.
6. Document the update procedure from upstream Zed.

### Current Status

As of 2026-03-25:

- `pwnsdx/gpui` exists at `https://github.com/pwnsdx/gpui`
- the initial `main` branch was created from a history-preserving subtree split of
  `vendor/gpui-0.2.2`
- the published split tip is commit `45c4c2ce282aafdc8c3b4c74539ccc9652575e0f`
- the initial fork baseline is tagged as `zed-source-69e2130`
- that initial branch currently carries the imported vendored baseline plus the
  later macOS select-all reentrancy fix
- the semantic material surface foundation was migrated into
  `pwnsdx/gpui` on branch `codex/material-system-foundation`
- that branch is currently published at commit
  `bd892c36d9e10e44df18d14467c7cf242d00d0c7`
- the pure-GPUI fallback backend was then refined on that same branch at
  commit `b10064823ca23971f4dc45cb7b152780dacb1394` with role-aware fallback
  rendering, inactive-window fallback rules, and reduced-transparency
  resolution at the framework layer
- City-G has started the app-side adoption pass for that API across the native
  sidebar/header shell, join shell, inspector cards, and grouped control rows
- City-G now consumes GPUI from that fork revision via a git patch instead of
  the vendored path dependency
- the stale vendored GPUI tree in `cityg/vendor/gpui-0.2.2` was retired after
  the fork switch and local validation

Known provenance notes:

- the vendored GPUI import inside `cityg` landed in commit `1e7afde`
- the later GPUI-specific crash fix landed in commit
  `7c662b279a0459a369ccdd9f6ca8831677b50497`
- the vendored crate metadata points to Zed commit
  `69e2130295c2649963eb639fc70b4f2ee8ea1624` for `crates/gpui`
- upstream Zed `main` was at `dbd95ea7427f2cdca33053e5c8b9b4d012d257d9`
  when this split decision was recorded

### Next Operational Steps

1. Define a repeatable sync workflow from upstream Zed to `pwnsdx/gpui`.
2. Continue moving framework-generic material work into `pwnsdx/gpui` while
   keeping product-specific shell composition in `cityg`.

### Timing

This fork split should happen soon, before the macOS-native backend and scroll
edge/background-extension work grow the patch stack further.

The semantic material API is exactly the kind of change that justifies moving to
an external maintained fork.

## References

Apple background and design guidance:

- [Meet Liquid Glass](https://developer.apple.com/videos/play/wwdc2025/219/)
- [Build an AppKit app with the new design](https://developer.apple.com/videos/play/wwdc2025/310/)
- [What’s New in SwiftUI](https://developer.apple.com/swiftui/whats-new/)

Current City-G and vendored GPUI implementation context:

- `crates/cityg-gui/src/native/app_shell.rs`
- `crates/cityg-gui/src/native/render_session.rs`
- `crates/cityg-gui/src/native/render_workspace.rs`
- `crates/cityg-gui/src/native/native_text_input.rs`
- `vendor/gpui-0.2.2/src/platform/mac/window.rs`
- `vendor/gpui-0.2.2/src/elements/canvas.rs`
- `vendor/gpui-0.2.2/src/elements/surface.rs`

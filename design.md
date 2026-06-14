---
version: alpha
name: Patter
description: >-
  system should a technical-minimalist aesthetic: monochromatic with a warm peach accent, hard geometric borders,
  dot-grid texture, and a deliberate rejection of soft shadows in favor of crisp, architect
colors:
  surface: '#ffffff'
  surface-dim: '#f6f6f4'
  surface-bright: '#ffffff'
  surface-container-lowest: '#fafaf8'
  surface-container-low: '#f4f7fb'
  surface-container: '#ebf0f5'
  surface-container-high: '#e3e3e6'
  surface-container-highest: '#eeeeee'
  on-surface: '#000000'
  on-surface-variant: '#4a4a4a'
  inverse-surface: '#1a1a1a'
  inverse-on-surface: '#ffffff'
  outline: '#000000'
  outline-variant: '#aaaaaa'
  surface-tint: '#cbcbcb'
  primary: '#000000'
  on-primary: '#ffffff'
  primary-container: '#1a1a1a'
  on-primary-container: '#ffffff'
  inverse-primary: '#ffffff'
  secondary: '#df9367'
  on-secondary: '#000000'
  secondary-container: '#fff8ef'
  on-secondary-container: '#c97a4c'
  tertiary: '#278eff'
  on-tertiary: '#ffffff'
  tertiary-container: '#ebf0f5'
  on-tertiary-container: '#1e6bd6'
  error: '#d32f2f'
  on-error: '#ffffff'
  error-container: '#ffebee'
  on-error-container: '#c62828'
  primary-fixed: '#1a1a1a'
  primary-fixed-dim: '#aaaaaa'
  on-primary-fixed: '#ffffff'
  on-primary-fixed-variant: '#cbcbcb'
  secondary-fixed: '#efc5ac'
  secondary-fixed-dim: '#c97a4c'
  on-secondary-fixed: '#000000'
  on-secondary-fixed-variant: '#df9367'
  tertiary-fixed: '#93c5fd'
  tertiary-fixed-dim: '#3b82f6'
  on-tertiary-fixed: '#000000'
  on-tertiary-fixed-variant: '#278eff'
  background: '#ffffff'
  on-background: '#000000'
  surface-variant: '#dad8de'
typography:
  display:
    fontFamily: Instrument Sans
    fontSize: 128px
    fontWeight: '700'
    lineHeight: 122px
    letterSpacing: '-0.035em'
  headline-lg:
    fontFamily: Instrument Sans
    fontSize: 64px
    fontWeight: '700'
    lineHeight: 65px
    letterSpacing: '-0.02em'
  headline-md:
    fontFamily: Instrument Sans
    fontSize: 40px
    fontWeight: '700'
    lineHeight: 48px
    letterSpacing: '-0.015em'
  title-lg:
    fontFamily: Instrument Sans
    fontSize: 28px
    fontWeight: '600'
    lineHeight: 36px
    letterSpacing: '-0.01em'
  body-lg:
    fontFamily: Instrument Sans
    fontSize: 21px
    fontWeight: '400'
    lineHeight: 31px
    letterSpacing: 0em
  body-md:
    fontFamily: Instrument Sans
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
    letterSpacing: 0em
  label-md:
    fontFamily: Instrument Sans
    fontSize: 14px
    fontWeight: '600'
    lineHeight: 20px
    letterSpacing: 0.01em
  label-sm:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.08em
  code:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
    letterSpacing: 0em
rounded:
  sm: 4px
  DEFAULT: 8px
  md: 12px
  lg: 16px
  xl: 24px
  full: 999px
spacing:
  unit: 4px
  xs: 4px
  sm: 12px
  md: 24px
  lg: 40px
  xl: 64px
  gutter: 32px
  container-max: 1280px
  container-tight: 1080px
elevation:
  none: none
  subtle: 0 1px 2px rgba(0, 0, 0, 0.04)
  card: 0 8px 32px rgba(0, 0, 0, 0.08)
  overlay: 0 24px 64px rgba(0, 0, 0, 0.18)
  stack: '0 8px 0 -1px #f6f6f4, 0 8px 0 0 #000000'
layout:
  containerMaxWidth: 1280px
  gridColumns: 12
components:
  button-primary:
    backgroundColor: '{colors.primary}'
    textColor: '{colors.on-primary}'
    typography: '{typography.label-md}'
    rounded: '{rounded.full}'
    padding: 10px 18px
    height: 40px
    border: 1.5px solid {colors.primary}
    transition: all 150ms cubic-bezier(0.2, 0.0, 0.0, 1)
  button-primary-hover:
    backgroundColor: '{colors.secondary}'
    textColor: '{colors.on-secondary}'
    borderColor: '{colors.primary}'
  button-secondary:
    backgroundColor: '{colors.surface}'
    textColor: '{colors.on-surface}'
    typography: '{typography.label-md}'
    rounded: '{rounded.full}'
    padding: 10px 18px
    height: 40px
    border: 1.5px solid {colors.primary}
  button-secondary-hover:
    backgroundColor: '{colors.surface-dim}'
  button-ghost:
    backgroundColor: transparent
    textColor: '{colors.on-surface}'
    typography: '{typography.label-md}'
    rounded: '{rounded.full}'
    padding: 10px 18px
    border: 1.5px solid transparent
  button-ghost-hover:
    backgroundColor: '{colors.surface-dim}'
  card:
    backgroundColor: '{colors.surface}'
    rounded: '{rounded.lg}'
    padding: '{spacing.md}'
    border: 1.5px solid {colors.outline-variant}
    boxShadow: '{elevation.card}'
  card-hover:
    backgroundColor: '{colors.surface-dim}'
    boxShadow: '{elevation.overlay}'
  input-field:
    backgroundColor: '{colors.surface-container-low}'
    textColor: '{colors.on-surface}'
    typography: '{typography.body-md}'
    rounded: '{rounded.DEFAULT}'
    padding: '{spacing.sm}'
    border: 1.5px solid {colors.outline-variant}
  input-field-focus:
    borderColor: '{colors.primary}'
    boxShadow: 0 0 0 3px rgba(0, 0, 0, 0.06)
  badge:
    backgroundColor: '{colors.secondary-container}'
    textColor: '{colors.on-secondary-container}'
    typography: '{typography.label-sm}'
    rounded: '{rounded.full}'
    padding: 2px 8px
    border: 1px solid {colors.secondary}
  eyebrow-tag:
    backgroundColor: '{colors.surface}'
    textColor: '{colors.on-surface}'
    typography: '{typography.label-sm}'
    rounded: '{rounded.full}'
    padding: 6px 12px
    border: 1.5px solid {colors.primary}
    display: inline-flex
    alignItems: center
    gap: 8px
  menu-item:
    backgroundColor: transparent
    textColor: '{colors.on-surface}'
    rounded: '{rounded.lg}'
    padding: 12px 14px
    transition: background 150ms cubic-bezier(0.2, 0.0, 0.0, 1)
  menu-item-hover:
    backgroundColor: '{colors.surface-dim}'
---

## Overview

Patter is a developer-focused, open-source SDK for voice AI that prioritizes technical clarity and architectural precision. The design system embodies a "Technical Minimalism" aesthetic: a near-monochromatic palette (pure black #000000 and white #ffffff) anchored by a warm peach accent (#df9367 and #c97a4c), combined with hard geometric borders, dot-grid textures, and deliberate rejection of soft shadows. The brand personality is direct, unpretentious, and engineer-first—every visual decision serves functional clarity over decoration. The UI evokes the precision of a technical blueprint: hard edges (border-radius: 4px to 24px, never rounded beyond necessity), 1.5px to 2px borders in pure black, and a subtle dot-grid background (radial-gradient with 18px spacing) that recalls graph paper. Voice: precise, matter-of-fact, no marketing flourish. Example: "Connect any agent to real phone calls in 4 lines of code. Python and TypeScript, MIT licensed, sub-500 ms latency."

## Colors

The color system is deliberately austere: a monochromatic foundation (black #000000, white #ffffff, grays from #1a1a1a to #cbcbcb) with a single warm accent—peach—used sparingly on CTAs, highlights, and brand moments. Primary (#000000) is the dominant ink color, used for text, borders, and the main call-to-action button (background: #000000, color: #ffffff, border: 1.5px solid #000000). Secondary (peach #df9367, with container #fff8ef and deep variant #c97a4c) appears on accent text (the italicized 'phone number' in the hero), menu icons, and badges. Tertiary (blue #278eff, container #ebf0f5) supports secondary actions and data visualization. Surface colors follow a strict hierarchy: surface (#ffffff) is the base, surface-dim (#f6f6f4) for subtle backgrounds, surface-container variants (#f

## Typography

The type system uses a single typeface family—Instrument Sans (from Google Fonts, weights 400–700)—paired with JetBrains Mono for code and labels. Display (128px, 700 weight, -0.035em letter-spacing, 122px line-height) is reserved for hero headlines and sets the tone of architectural boldness. Headline-lg (64px, 700 weight, -0.02em) and headline-md (40px, 700 weight) handle section titles with tight line-height (1.0–1.15) to reinforce density. Body-lg (21px, 400 weight, 1.5 line-height) is used for hero subheadings and prominent copy; body-md (16px, 400 weight, 1.4 line-height) is the default paragraph text. Label-md (14px, 600 weight, 0.01em letter-spacing) is applied to buttons and interactive labels; label-sm (12px, 500 weight, 0.08em letter-spacing, JetBrains Mono) is used for eyebrow

## Layout

The layout system uses a fixed 12-column grid with a max-width of 1280px and a gutter of 32px (padding: 0 32px on the container). A tighter variant, container-tight, constrains content to 1080px for focused reading. The hero section spans full-width with centered content, using a dot-grid background (radial-gradient at 18px spacing, masked with an elliptical radial-gradient to fade at edges) to add texture without visual noise. Section spacing follows a semantic scale: lg (40px) separates major sections, md (24px) separates subsections, and sm (12px) separates inline elements. The dot-grid background (--dot-grid: radial-gradient(circle at 1px 1px, #dad8de 1px, transparent 0); background-size: 18px 18px) is applied selectively to hero and feature sections to reinforce the technical aestheti

## Elevation & Depth

Depth is conveyed through hard borders and stacked shadows rather than soft blur. Level 1 (Base): flat surfaces with 1.5px solid borders in #000000 or #aaaaaa. Level 2 (Cards/Containers): 1.5px border + box-shadow: 0 8px 32px rgba(0, 0, 0, 0.08) for subtle lift. Level 3 (Modals/Overlays): 1.5px border + box-shadow: 0 24px 64px rgba(0, 0, 0, 0.18) for pronounced depth. A distinctive 'stack' shadow (box-shadow: 0 8px 0 -1px #f6f6f4, 0 8px 0 0 #000000) is used on certain interactive elements to create a physical 3D offset effect, evoking stacked paper or layered cards. Hover states increase shado

## Shapes

The shape philosophy is 'Architectural Sharpness': borders and radii are intentionally minimal and geometric, never organic. Buttons and pills use border-radius: 999px (full pill shape) for primary CTAs and secondary actions, creating a distinctive rounded-rectangle silhouette. Cards and containers use border-radius: 16px (lg) for standard containers and 24px (xl) for elevated modals, maintaining a clean, technical appearance. Input fields and smaller components use border-radius: 8px (DEFAULT) or 12px (md). The eyebrow tag uses 999px to match button styling. All borders are 1.5px solid (--bw-

## Components

### Action Elements
Buttons follow a strict two-tier system: primary (background: #000000, color: #ffffff, border: 1.5px solid #000000, border-radius: 999px, padding: 10px 18px, height: 40px) for main CTAs like 'Get a demo →', and secondary (background: #ffffff, color: #000000, border: 1.5px solid #000000, border-radius: 999px) for supporting actions. On hover, primary buttons shift to background: #df9367 (peach) with border: 1.5px solid #000000, maintaining the border for visual continuity. Secondary buttons hover to background: #f6f6f4 (surface-dim). All buttons use transition: all 150ms cubic-bezier(0.2, 0.0, 0.0, 1) for snappy, predictable motion. Ghost buttons (transparent background, 1.5px border, no fill) are used for tertiary actions and hover to background: #f6f6f4. Install pills

## Do's and Don'ts

**Do**
- Do use pure black (#000000) and white (#ffffff) as the primary palette; reserve peach (#df9367) for accents and brand moments only.
- Do apply hard borders (1.5px solid #000000 or #aaaaaa) instead of soft shadows; use stacked shadows (0 8px 0 -1px #f6f6f4, 0 8px 0 0 #000000) for 3D depth on interactive elements.
- Do use Instrument Sans for all body and headline text; use JetBrains Mono exclusively for code, labels, and monospace content.
- Do maintain border-radius consistency: 999px for pills/buttons, 16px for cards, 8px for inputs, 4px for small components.
- Do apply negative letter-spacing (-0.035em to -0.01em) on headlines and 0em on body text to control visual density.
- Do use the dot-grid texture (radial-gradient at 18px spacing, masked elliptically) sparingly on hero and feature sections to reinforce the technical aesthetic.

**Don't**
- Don't use soft shadows, blur filters, or transparency overlays; every layer must have a hard 1.5px border and opaque background.
- Don't mix typefaces; Instrument Sans is the only sans-serif; JetBrains Mono is the only monospace.
- Don't use rounded corners beyond 24px (xl) or soften pill buttons below 999px border-radius.
- Don't apply peach (#df9367) to backgrounds or large surfaces; reserve it for text accents, icons, and hover states on primary buttons.
- Don't use color gradients or multi-color backgrounds; every surface must be a single, opaque hex color from the palette.
- Don't animate opacity or blur; use transform: translateY() and transition: all 150ms cubic-bezier(0.2, 0.0, 0.0, 1) for all motion.

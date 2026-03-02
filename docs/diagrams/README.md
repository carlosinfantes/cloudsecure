# CloudSecure Diagrams

This folder contains Draw.io diagrams for the CloudSecure presentation.

## Diagram Files

| File | Description |
|------|-------------|
| `cloudsecure-architecture.drawio` | High-level system architecture |
| `assessment-workflow.drawio` | Assessment process swimlane diagram |
| `security-model.drawio` | Security controls and access model |
| `analyzer-coverage.drawio` | 7 analyzers and coverage breakdown |

## How to Open and Edit

### Option 1: Draw.io Desktop
1. Download from [draw.io](https://www.drawio.com/)
2. Open any `.drawio` file
3. Edit and save

### Option 2: Draw.io Online
1. Go to [app.diagrams.net](https://app.diagrams.net)
2. File > Open from > Device
3. Select the `.drawio` file
4. Edit in browser

### Option 3: VS Code Extension
1. Install "Draw.io Integration" extension
2. Open `.drawio` files directly in VS Code

## AWS Icons

These diagrams use the AWS Architecture Icons. To access them in Draw.io:

1. Open Draw.io
2. Click "+ More Shapes" (bottom left)
3. Search for "AWS" in the shapes library
4. Enable "AWS 2024" (or latest) icon set

## Exporting Diagrams

### Export to PNG (for slides)
1. Open diagram in Draw.io
2. File > Export as > PNG...
3. Set scale to 2x for high resolution
4. Set border width to 10
5. Save to `exports/` folder

### Export to SVG (for web)
1. Open diagram in Draw.io
2. File > Export as > SVG...
3. Save to `exports/` folder

### Batch Export (all diagrams)
For consistency, export all diagrams at once:
1. Open each diagram
2. Export with these settings:
   - Format: PNG
   - Scale: 200%
   - Border: 10px
   - Background: White

## Export Folder Structure

```
exports/
├── architecture.png
├── workflow.png
├── security-model.png
└── analyzer-coverage.png
```

## Embedding in Marp Presentation

After exporting, update the presentation with:

```markdown
![Architecture](../diagrams/exports/architecture.png)
```

## Color Palette

The diagrams follow this consistent color scheme:

| Purpose | Color | Hex |
|---------|-------|-----|
| CloudSecure Platform | Blue | #E6F2FF / #147EB4 |
| Customer Account | Orange | #FFF4E6 / #FF9900 |
| Security/IAM | Red | #FFCDD2 / #C62828 |
| Storage/Data | Green | #E8F5E9 / #4CAF50 |
| AI/Bedrock | Teal | #E0F2F1 / #00695C |
| Network | Purple | #E1BEE7 / #7B1FA2 |
| Prowler | Dark Gray | #263238 |

## Tips

1. **Consistency**: Use the same icon style throughout
2. **Alignment**: Use Draw.io's alignment tools
3. **Spacing**: Keep consistent spacing between elements
4. **Labels**: Use clear, concise labels
5. **Arrows**: Use consistent arrow styles

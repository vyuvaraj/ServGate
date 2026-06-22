import os
import zipfile
import math
from PIL import Image, ImageDraw, ImageFilter

def create_isometric_s_icon(size=1024):
    # Base canvas with transparency
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    cx, cy = size / 2, size / 2
    scale = size * 0.4
    
    # Define colors matching image_725395.png (Purple to Cyan gradients, metallic tech feel)
    c_cyan = (0, 180, 255, 255)
    c_blue = (40, 90, 230, 255)
    c_indigo = (75, 30, 180, 255)
    c_purple = (115, 40, 215, 255)
    c_dark_purple = (45, 15, 100, 255)
    c_bright_neon = (0, 240, 255, 255)
    
    # Helper for isometric projection coordinates
    def pt(hx, hy, hz=0):
        # Isometric transformation coordinates
        # hx, hy are on the flat plane, hz is height
        x = cx + scale * (hx - hy) * math.cos(math.radians(30))
        y = cy + scale * (hx + hy) * math.sin(math.radians(30)) - scale * hz
        return (x, y)

    # Let's construct a precisely layered 3D blocky/ribbon Hexagonal "S" structure.
    # To make it look incredibly clean, we'll draw distinct interlocking isometric facets.
    
    # 1. Back/Bottom segments (Deep shadows/purples)
    draw.polygon([pt(0, 0, -0.1), pt(0.6, 0, -0.1), pt(0.6, 0.6, -0.1), pt(0, 0.6, -0.1)], fill=c_dark_purple)
    
    # 2. Main S Ribbon Segments
    # Top bar of the S
    draw.polygon([pt(-0.5, -0.8, 0.2), pt(0.5, -0.8, 0.2), pt(0.5, -0.4, 0.2), pt(-0.5, -0.4, 0.2)], fill=c_bright_neon)
    draw.polygon([pt(-0.5, -0.8, 0), pt(-0.5, -0.8, 0.2), pt(-0.5, -0.4, 0.2), pt(-0.5, -0.4, 0)], fill=c_blue)
    draw.polygon([pt(-0.5, -0.4, 0), pt(-0.5, -0.4, 0.2), pt(0.5, -0.4, 0.2), pt(0.5, -0.4, 0)], fill=c_blue)

    # Diagonal/Middle slide of S
    draw.polygon([pt(-0.5, -0.4, 0.1), pt(0.5, 0.4, 0.1), pt(0.1, 0.5, 0.1), pt(-0.9, -0.3, 0.1)], fill=c_blue)
    
    # Bottom bar of the S
    draw.polygon([pt(-0.5, 0.4, 0), pt(0.5, 0.4, 0), pt(0.5, 0.8, 0), pt(-0.5, 0.8, 0)], fill=c_purple)
    draw.polygon([pt(-0.5, 0.4, -0.2), pt(-0.5, 0.4, 0), pt(0.5, 0.4, 0), pt(0.5, 0.4, -0.2)], fill=c_indigo)
    draw.polygon([pt(0.5, 0.4, -0.2), pt(0.5, 0.4, 0), pt(0.5, 0.8, 0), pt(0.5, 0.8, -0.2)], fill=c_dark_purple)

    # Re-draw clean hexagonal ring frame overlay to match image_725395.png's beautiful sleek geometry
    # Let's clear and create an absolute crisp modern vector representation of the exact logo geometry.
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Precise Hexagonal S Path coordinates (Outer ring with inner cutouts)
    w = size * 0.18 # Thickness
    r = size * 0.38 # Radius
    
    def hex_pt(angle_deg, radius_val):
        a = math.radians(angle_deg - 90) # Top vertex point
        return (cx + radius_val * math.cos(a), cy + radius_val * math.sin(a))

    # Outer hexagon vertices
    p1, p2, p3, p4, p5, p6 = [hex_pt(i * 60, r) for i in range(6)]
    # Inner hexagon vertices
    i1, i2, i3, i4, i5, i6 = [hex_pt(i * 60, r - w) for i in range(6)]
    
    # Draw segments with gradients to look exactly like the multi-faceted dimensional S icon in image_725395.png
    # Top-Left side (Cyan/Blue transition)
    draw.polygon([p6, p1, i1, i6], fill=(0, 220, 255, 255))
    draw.polygon([p1, p2, i2, i1], fill=(0, 160, 255, 255))
    
    # Middle diagonal spine forming the 'S' connection
    draw.polygon([i1, p2, p5, i4], fill=(60, 100, 240, 255))
    
    # Bottom-Right side (Purple/Indigo transition)
    draw.polygon([p3, p4, i4, i3], fill=(110, 45, 210, 255))
    draw.polygon([p4, p5, i5, i4], fill=(80, 30, 185, 255))
    
    # Subtle inner overlays to give the interlocking ribbon look
    draw.polygon([p2, p3, i3, i2], fill=(45, 70, 200, 255))
    draw.polygon([p5, p6, i6, i5], fill=(130, 55, 230, 255))
    
    # Clean inner channel cuts to finalize the distinct "S" shape
    # Cut top right inner side to split the ring
    gap = size * 0.04
    draw.polygon([hex_pt(40, r+10), hex_pt(80, r+10), cx, cy], fill=(0, 0, 0, 0)) # Masking
    
    # Let's do a direct pristine procedural render of the continuous isometric S ribbon:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Let's draw the precise 6 facets of the outer loop matching image_725395.png
    # Facet 1: Top horizontal left-to-right bar
    draw.polygon([p6, p1, i1, i6], fill=(0, 235, 255, 255))
    draw.polygon([p1, p2, i2, i1], fill=(0, 185, 255, 255))
    # Facet 2: Diagonal fold down-left
    draw.polygon([i1, p2, hex_pt(120, r-w*0.5), hex_pt(180, r-w*1.5)], fill=(30, 120, 245, 255))
    # Facet 3: Spine crossover
    draw.polygon([p2, p3, p5, p6], fill=(70, 50, 215, 255))
    # Clean masking to make the perfect S shape look identical to image_725395.png
    img_final = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw_f = ImageDraw.Draw(img_final)
    
    # Draw exact matching geometry from image_725395.png
    # A beautifully shaded continuous hexagonal S ribbon
    draw_f.polygon([p6, p1, p2, i2, i1, i6], fill=(0, 210, 255, 255)) # Upper shelf
    draw_f.polygon([p2, p3, i3, i2], fill=(50, 110, 240, 255))        # Right downward wall
    draw_f.polygon([i1, p2, p5, i4], fill=(90, 60, 220, 255))         # Center diagonal bridge
    draw_f.polygon([p5, p6, i6, i5], fill=(125, 50, 225, 255))        # Left downward wall
    draw_f.polygon([p3, p4, p5, i5, i4, i3], fill=(150, 60, 240, 255)) # Lower shelf

    return img_final

# Generate standalone icon assets
base_icon = create_isometric_s_icon(1024)
sizes = [16, 32, 48, 64, 128, 256, 512, 1024]
pack_files = []

for s in sizes:
    resized = base_icon.resize((s, s), Image.Resampling.LANCZOS)
    filename = f"servgate_standalone_icon_{s}x{s}.png"
    resized.save(filename, "PNG")
    pack_files.append(filename)

# Save high-quality ico version
ico_name = "servgate_standalone_icon.ico"
base_icon.save(ico_name, format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
pack_files.append(ico_name)

# Package into a clean ZIP archive
zip_filename = "servgate_standalone_logo_pack.zip"
with zipfile.ZipFile(zip_filename, 'w') as zf:
    for f in pack_files:
        zf.write(f)
        os.remove(f)

print(f"Archive generated: {zip_filename}")
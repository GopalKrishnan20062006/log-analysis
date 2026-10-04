from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"

print("Challenge 2 - Log Analysis")
print("=" * 40)

print(f"Data directory:   {DATA_DIR}")
print(f"Output directory: {OUTPUT_DIR}")

print("\nFiles available:")

for file in DATA_DIR.iterdir():
    print(f"  {file.name}")
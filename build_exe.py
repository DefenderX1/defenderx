"""
DefendX — PyInstaller Build Script
Packages the DefendX application into a standalone Windows EXE.
"""

import PyInstaller.__main__
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(PROJECT_ROOT, 'Models')
APP_DIR = os.path.join(PROJECT_ROOT, 'app')
EDA_DIR = os.path.join(PROJECT_ROOT, 'EDA')


def build():
    """Build the DefendX executable."""
    print("=" * 50)
    print("  DefendX — Building Executable")
    print("=" * 50)
    
    # Collect data files
    datas = []
    
    # Include trained models if they exist
    model_files = [
        'isolation_forest.pkl',
        'random_forest.pkl',
        'scaler.pkl',
        'model_config.json',
        'threat_scores.csv',
        'feature_matrix.csv',
        'label_mappings.json',
    ]
    
    for mf in model_files:
        mf_path = os.path.join(MODELS_DIR, mf)
        if os.path.exists(mf_path):
            datas.append(f'--add-data={mf_path};Models')
    
    # Include training plots
    plots_dir = os.path.join(MODELS_DIR, 'training_plots')
    if os.path.exists(plots_dir):
        datas.append(f'--add-data={plots_dir};Models/training_plots')
    
    # Include EDA outputs
    eda_outputs = os.path.join(EDA_DIR, 'outputs')
    if os.path.exists(eda_outputs):
        datas.append(f'--add-data={eda_outputs};EDA/outputs')
    
    # Include User ui wallpaper assets
    wallpaper_dir = os.path.join(PROJECT_ROOT, 'User ui wallpaper')
    if os.path.exists(wallpaper_dir):
        datas.append(f'--add-data={wallpaper_dir};User ui wallpaper')
    
    # Build arguments
    args = [
        os.path.join(PROJECT_ROOT, 'defendx.py'),
        '--name=DefendX',
        '--onefile',
        '--windowed',
        f'--distpath={os.path.join(PROJECT_ROOT, "dist")}',
        f'--workpath={os.path.join(PROJECT_ROOT, "build")}',
        f'--specpath={PROJECT_ROOT}',
        '--noconfirm',
        '--clean',
        # Hidden imports
        '--hidden-import=sklearn',
        '--hidden-import=sklearn.ensemble',
        '--hidden-import=sklearn.preprocessing',
        '--hidden-import=sklearn.model_selection',
        '--hidden-import=sklearn.metrics',
        '--hidden-import=sklearn.utils._typedefs',
        '--hidden-import=sklearn.utils._heap',
        '--hidden-import=sklearn.utils._sorting',
        '--hidden-import=sklearn.utils._vector_sentinel',
        '--hidden-import=matplotlib',
        '--hidden-import=matplotlib.backends.backend_tkagg',
        '--hidden-import=seaborn',
        '--hidden-import=joblib',
        '--hidden-import=reportlab',
        '--hidden-import=PIL',
        '--hidden-import=watchdog',
        '--hidden-import=plyer',
        '--hidden-import=tkcalendar',
        '--hidden-import=huggingface_hub',
        '--hidden-import=huggingface_hub.inference',
    ]
    
    # Add data files
    args.extend(datas)
    
    print(f"\nBuild args ({len(args)}):")
    for arg in args:
        print(f"  {arg}")
    
    print("\nStarting PyInstaller build...")
    print("This may take 2-5 minutes...\n")
    
    PyInstaller.__main__.run(args)
    
    exe_path = os.path.join(PROJECT_ROOT, 'dist', 'DefendX.exe')
    if os.path.exists(exe_path):
        size_mb = os.path.getsize(exe_path) / (1024 * 1024)
        print(f"\n{'=' * 50}")
        print(f"  ✅ Build successful!")
        print(f"  EXE: {exe_path}")
        print(f"  Size: {size_mb:.1f} MB")
        print(f"{'=' * 50}")
    else:
        print("\n❌ Build failed — EXE not found")


if __name__ == '__main__':
    build()

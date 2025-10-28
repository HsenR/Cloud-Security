#!/usr/bin/env python3
print("🧪 Testing fixed imports...")

try:
    from src.scanner import CloudSecurityScanner
    print("✅ CloudSecurityScanner imported successfully!")
    
    scanner = CloudSecurityScanner()
    print("✅ Scanner object created successfully!")
    print("🎉 All imports fixed! Ready to test AWS connectivity.")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
except Exception as e:
    print(f"❌ Other error: {e}")

#!/bin/bash
apps=("wx3a0011e012ee829f" "wx71ec0d0b2067ad18" "wx9430f74fda7b3c37" "wxb4c434b2298416ed" "wxd91c461252e017d4")
for app in "${apps[@]}"; do
  echo "=========================================="
  echo "Testing: $app"
  echo "=========================================="
  python main.py --source "unpacked/$app" --output "output_retest_$app" 2>&1 | grep -E "(检测目标|污点数据流|MiniCPRF 漏洞数|发现.*漏洞)"
  echo ""
done

#!/bin/bash
# verify_migration.sh — post-migration checks for a LiteOS SDK -> OpenHarmony lite product.
#
# Usage:
#   ./verify_migration.sh \
#       --root  /path/to/ohos_tree \
#       --soc   device/soc/hisilicon/ws53v106 \
#       --board device/board/hisilicon/fbb_ws53 \
#       --vendor vendor/hisilicon/fbb_ws53 \
#       --product fbb_ws53 \
#       --target ws53_liteos_app \
#       [--chip-dir ws53v106] \
#       [--stale 'ws63|3863|WS63'] \
#       [--symbol 'samgr|Ble|HiLog|OHOS_SystemInit']
#
# Checks:
#   1. residual identifiers in the three integration layers (adapter/board/vendor)
#   2. every include dir in board liteos_m/config.gni exists
#   3. the product's firmware ELF contains OHOS symbols (link closure)
#   4. fwpkg artifacts exist
#
# Exit code 0 = all checks passed (warnings allowed), 1 = a hard failure.

set -u

ROOT=""
SOC=""
BOARD=""
VENDOR=""
PRODUCT=""
TARGET=""
CHIP_DIR=""
STALE='ws63|3863|WS63'
SYMBOL='samgr|Ble|HiLog|OHOS_SystemInit'

while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT="$2"; shift 2;;
    --soc) SOC="$2"; shift 2;;
    --board) BOARD="$2"; shift 2;;
    --vendor) VENDOR="$2"; shift 2;;
    --product) PRODUCT="$2"; shift 2;;
    --target) TARGET="$2"; shift 2;;
    --chip-dir) CHIP_DIR="$2"; shift 2;;
    --stale) STALE="$2"; shift 2;;
    --symbol) SYMBOL="$2"; shift 2;;
    -h|--help) sed -n '2,30p' "$0"; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

if [ -z "$ROOT" ] || [ -z "$SOC" ] || [ -z "$BOARD" ] || [ -z "$VENDOR" ] || [ -z "$PRODUCT" ] || [ -z "$TARGET" ]; then
  echo "missing required args (see --help)" >&2
  exit 2
fi

FAIL=0
ok()   { echo "  [ OK ] $1"; }
warn() { echo "  [WARN] $1"; }
bad()  { echo "  [FAIL] $1"; FAIL=1; }

echo "== 1. residual identifiers in integration layers =="
# Allow matches that are only in comments / explanatory text about the source chip.
for layer in "$ROOT/$SOC/adapter" "$ROOT/$BOARD" "$ROOT/$VENDOR"; do
  if [ -d "$layer" ]; then
    hits=$(grep -rnE "$STALE" "$layer" 2>/dev/null | grep -vE 'integration layer|unlike |no longer exist|case study|sibling' | head -20)
    if [ -n "$hits" ]; then
      warn "possible stale identifiers under $layer:"
      echo "$hits" | sed 's/^/        /'
    else
      ok "clean: $layer"
    fi
  else
    warn "missing layer dir: $layer"
  fi
done

echo "== 2. board config.gni include dirs exist =="
CFG="$ROOT/$BOARD/liteos_m/config.gni"
if [ ! -f "$CFG" ]; then
  bad "no board config.gni at $CFG"
else
  # Extract ${ohos_root_path}... entries, expand placeholders, check existence.
  grep -oE '\$\{ohos_root_path\}[^"]*' "$CFG" | while read -r raw; do
    p=$(printf '%s' "$raw" \
      | sed "s#\${ohos_root_path}#$ROOT/#; s#\${sdk}#sdk#g; s#//#/#g")
    if [ -e "$p" ]; then
      echo "  [ OK ] $p"
    else
      echo "  [FAIL] missing include: $p"
    fi
  done
  # propagate a failure from the subshell
  if grep -oE '\$\{ohos_root_path\}[^"]*' "$CFG" | while read -r raw; do
      p=$(printf '%s' "$raw" | sed "s#\${ohos_root_path}#$ROOT/#; s#\${sdk}#sdk#g; s#//#/#g")
      [ -e "$p" ] || exit 1
    done; then :; else bad "one or more board include dirs are missing"; fi
fi

echo "== 3. link closure: firmware ELF contains OHOS symbols =="
SDK="$ROOT/$SOC/sdk"
ELF=$(find "$SDK/output" -name 'application.elf' 2>/dev/null | head -1)
MAP=$(find "$SDK/output" -name 'application.map' 2>/dev/null | head -1)
if [ -z "$ELF" ]; then
  warn "no firmware application.elf under $SDK/output (L1/L2 not built yet?)"
else
  NM=$(find "$SDK/tools" -name 'riscv32-linux-musl-nm' 2>/dev/null | head -1)
  map_refs=0
  [ -n "$MAP" ] && map_refs=$(grep -cE 'libs/ohos/.*/lib.*\.a' "$MAP" 2>/dev/null)
  if [ -z "$NM" ]; then
    warn "no riscv32-linux-musl-nm under $SDK/tools; cannot inspect $ELF"
  else
    count=$("$NM" "$ELF" 2>/dev/null | grep -icE "$SYMBOL")
    if [ "$count" -gt 0 ]; then
      ok "ELF contains $count OHOS symbol(s) matching '$SYMBOL' (linked AND retained)"
    elif [ "$map_refs" -gt 0 ]; then
      bad "map references $map_refs OHOS lib(s) but the ELF has no '$SYMBOL' symbols:"
      bad "  linked but GARBAGE-COLLECTED. Add the OHOS startup bridge (ohos_start ->"
      bad "  OHOS_SystemInit) and the linker __zinitcall_* sections. See Phase 2.5."
    else
      bad "ELF has NO OHOS symbols and the map references no libs/ohos/*.a:"
      bad "  compiled but NOT LINKED. Check the libs_url/<chip>/cmake/ohos.cmake hook"
      bad "  in protocol/CMakeLists.txt and that hm_build.sh populated libs/ohos/<target>."
    fi
  fi
  if [ -n "$MAP" ]; then
    [ "$map_refs" -gt 0 ] && ok "map references $map_refs OHOS lib(s) from libs/ohos/" \
                         || bad "map references no libs/ohos/*.a"
  fi
fi

echo "== 4. product artifacts =="
# fwpkg layout varies by SDK: ws53 uses pack_all_core/<target>/, bs21e uses <target>/
# directly. Search under the product out dir.
fw=$(find "$ROOT/out/$PRODUCT/$PRODUCT" -name '*.fwpkg' 2>/dev/null | head -20)
if [ -n "$fw" ]; then
  ok "fwpkg present:"
  echo "$fw" | sed 's/^/        /'
else
  warn "no fwpkg under $ROOT/out/$PRODUCT/$PRODUCT (run: hb build)"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "RESULT: PASS (warnings may need review)"
else
  echo "RESULT: FAIL"
fi
exit $FAIL

#!/bin/bash
set -e
set -u

do_assemble() {
  cat apf_interpreter_source.c
}

do_test() {
  diff -q <(do_assemble) apf_interpreter.c
}

main() {
  local -r me="${0##*/}"
  case "${me}" in
    apf_interpreter_assemble.sh)
      do_assemble > apf_interpreter.c
      ;;
    apf_assemble_test.sh)
      do_test
      ;;
    *)
      echo "Unknown $0" 1>&2
      return 1
      ;;
  esac
}

main "$@"; exit

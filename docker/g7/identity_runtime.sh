#!/bin/bash

# Stage only the credential material selected by the admitted OIDC mode.
# Arguments make the filesystem roots injectable for focused packaging tests.
uvm_g7_stage_identity_material() {
  local secrets_root=$1 runtime_secret_root=$2 state_root=$3 auth_mode=$4 deployment_mode=$5
  local verification_only=$6 recovery_stage=$7
  local demo_secret="$secrets_root/demo-admin-credentials"
  local publisher_config="$secrets_root/okta-publisher.json"
  local publisher_key="$secrets_root/okta_service_private_key"

  unset UVM_OIDC_DEMO_CREDENTIALS_FILE UVM_G7_OKTA_PUBLISHER_CONFIG_FILE
  if [[ $verification_only == 1 || $recovery_stage == control-only || $auth_mode != oidc ]]; then
    return 0
  fi

  case "$deployment_mode" in
    demo)
      if [[ -e $publisher_config || -e $publisher_key ]]; then
        echo 'G7_IDENTITY_MODE=demo-rejects-external-publisher-material' >&2
        return 70
      fi
      if [[ ! -f $demo_secret || -L $demo_secret || ! -s $demo_secret ]]; then
        echo 'G7_IDENTITY_DEMO_CREDENTIAL=missing-or-invalid' >&2
        return 70
      fi
      install -d -o uvm -g uvm -m 0700 "$state_root"
      install -o uvm -g uvm -m 0600 "$demo_secret" "$state_root/demo-admin-credentials.json"
      UVM_OIDC_DEMO_CREDENTIALS_FILE="$state_root/demo-admin-credentials.json"
      ;;
    external)
      if [[ -e $demo_secret || -e $state_root/demo-admin-credentials.json ]]; then
        echo 'G7_IDENTITY_MODE=external-rejects-demo-credential' >&2
        return 70
      fi
      if [[ -e $publisher_config || -e $publisher_key ]]; then
        if [[ ! -f $publisher_config || -L $publisher_config || ! -s $publisher_config ||
              ! -f $publisher_key || -L $publisher_key || ! -s $publisher_key ]]; then
          echo 'G7_IDENTITY_OKTA_MATERIAL=incomplete-or-invalid' >&2
          return 70
        fi
        install -d -o root -g uvm -m 0750 "$runtime_secret_root"
        install -o root -g uvm -m 0440 "$publisher_config" "$runtime_secret_root/okta-publisher.json"
        install -o uvm -g uvm -m 0400 "$publisher_key" "$runtime_secret_root/okta_service_private_key"
        UVM_G7_OKTA_PUBLISHER_CONFIG_FILE="$runtime_secret_root/okta-publisher.json"
      fi
      ;;
    *)
      echo 'G7_IDENTITY_MODE=unsupported' >&2
      return 70
      ;;
  esac
}

uvm_g7_okta_publisher_healthy() {
  local config_file=$1 pid_file=$2 python_bin=$3 pid
  [[ -e $config_file ]] || return 0
  [[ -s $pid_file ]] || return 1
  pid=$(cat "$pid_file") || return 1
  [[ $pid =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  "$python_bin" -m uvm.auth.okta_publisher --config "$config_file" --status \
    >/dev/null 2>&1
}

uvm_g7_invalidate_publisher_readiness() {
  local publisher_state=$1 status_file="$1/status.json"
  [[ -e $publisher_state || -L $publisher_state ]] || return 0
  [[ -d $publisher_state && ! -L $publisher_state ]] || {
    echo 'G7_IDENTITY_OKTA_STATE=invalid-directory' >&2
    return 70
  }
  if [[ -e $status_file || -L $status_file ]]; then
    [[ -f $status_file && ! -L $status_file ]] || {
      echo 'G7_IDENTITY_OKTA_STATUS=invalid-file' >&2
      return 70
    }
    rm -- "$status_file"
  fi
}

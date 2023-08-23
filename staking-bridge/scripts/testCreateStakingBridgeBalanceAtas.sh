solana_config=$(solana config get)
keypair_path=$(echo "$solana_config" | grep "Keypair Path" | awk '{print $3}')

if [ -z "$keypair_path" ]; then
  echo "Error: fee payer keypair path not found"
  exit 1
fi

feePayerSecret=$(cat $keypair_path) anchor run test-create-staking-bridge-balance-atas -- --skip-deploy

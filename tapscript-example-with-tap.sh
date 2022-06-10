# https://github.com/bitcoin-core/btcdeb/blob/master/doc/tapscript-example-with-tap.md

# Follows the example given above to create a direct spend Taproot transaction (given private key)
# and a script spend Tapscript transaction (given only one participant's private key).  Can be used
# as a general creator of a two-spending-alternative (one branch) Taproot transaction by replacing
# the two scripts below (`script_alice` and `script_bob`).

# Prerequisites:
#
# 1) assumes `bitcoind`` installed
# 2) assumes `btc-run` starts `bitcoind` on `regtest` network
# 3) assumes `btc-clear` clears the `regtest` storage for `bitcoind`
# 4) assumes `btc-kill` kills `bitcoind` process (either via `stop` RPC or just `kill -9`)
# 5) assumes `btc-cli` runs the bitcoin CLI tool on `regtest` network
# 6) uses `jq` (JSON CLI query)
# 7) uses `btcdeb` and `tap` tools from `https://github.com/david-bakin/btcdeb` branch `force_logging_option`
#    (which is a fork of `https://github.com/bitcoin-core/btcdeb` that adds the ability to have full
#    `tap` logging even though directed to a pipe)


sha256() {
    echo -n ${1} | openssl dgst -sha256 -binary | xxd -p -c 256
}

ripemd160() {
    echo -n ${1} | openssl dgst -rmd160 -binary | xxd -p -c 256
}

hash160() {
    echo -n "$(ripemd160 $(sha256 ${1}))"
}

reversehexbytes() {
    local bin=${1}
    local bout="$(echo ${bin} | fold -w2 | tac | tr -d '\n')"
    echo -n ${bout}
}

# Some housekeeping
if [ -t 1 ]; then
   RED="$(tput setaf 196)❌ ❌ ❌   "
   YELLOW=$(tput setaf 230)
   BLUE=$(tput setaf 203)
   GREEN="$(tput setaf 118)🢂 🢂 🢂   "
   ORANGE=$(tput setaf 208)
   ITAL=$(tput sitm)
   RESET=$(tput sgr0)
else
   RED='❌ ❌ ❌   '
   YELLOW='―――――――   '
   BLUE=
   GREEN='🢂 🢂 🢂   '
   ORANGE=
   ITAL=
   RESET=
fi

color() {
    local CCC="$1"
    shift
    echo "${!CCC}$*${RESET}"
}

# MAKE SURE BITCOIND IS READY TO GO
printf "$(color GREEN clearing regtest blockchain and starting bitcoind)\n"
btc-kill
sleep 1
btc-clear
btc-run
btc-cli -rpcwait getblockchaininfo >/dev/null

# CREATE WALLET
printf "$(color GREEN creating wallet, setting fee)\n"
btc-cli createwallet 'tapscript-example-wallet' false false '' false true false
btc-cli settxfee 0.00001 > /dev/null
echo

# START A BLOCKCHAIN
printf "$(color GREEN creating blockchain w/ 200BTC)\n"
blocks_money=$(btc-cli -generate 4 1000)
addr_funds=$(echo ${blocks_money} | jq -r '.address')
blocks_confirmations=$(btc-cli -generate 100)
addr_funds_received_txs=$(btc-cli listreceivedbyaddress 1 false false $addr_funds | jq '.[0] | .["txids"]')

echo addr_funds ' ' ${addr_funds}
printf "addr_funds_received_txs $(echo ${addr_funds_received_txs} | jq '.')\n"
echo

# now have 200BTC confirmed

# SCENARIO

printf "$(color GREEN setting scenario parameters)\n"

alice_privkey=2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90
alice_pubkey=9997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803be
bob_privkey=81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9
bob_pubkey=4edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10
internal_privkey=1229101a0fcf2104e8808dab35661134aa5903867d44deb73ce1c7e4eb925be8
internal_pubkey=f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c

privkey=${internal_privkey}
pubkey=${internal_pubkey}

preimage=107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f
preimage_sha256=6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333

script_alice="[144 OP_CHECKSEQUENCEVERIFY OP_DROP ${alice_pubkey} OP_CHECKSIG ]"
script_bob="[OP_SHA256 ${preimage_sha256} OP_EQUALVERIFY ${bob_pubkey} OP_CHECKSIG ]"

echo privkey '(alice)        ' ${alice_privkey}
echo pubkey '(alice)         ' ${alice_pubkey}
echo script_alice '          ' ${script_alice}
echo privkey '(bob)          ' ${bob_privkey}
echo pubkey '(bob)           ' ${bob_pubkey}
echo script_bob '            ' ${script_bob}
echo privkey '(internal)     ' ${privkey} " ($(color ITAL random number to unlock this Taproot transaction))"
echo pubkey '(internal)      ' ${pubkey}
echo "HASH160(pubkey int)" '   ' $(hash160 ${pubkey})
echo preimage '              ' ${preimage} " ($(color ITAL random number used as unlock secret for Bob\'s script))"
echo preimage_sha256 '       ' ${preimage_sha256}
echo

# GENERATING A TAPROOT COMMITMENT

## generate tweaked pubkey for funding
printf "$(color GREEN tap-send \(to get the send-to-address to fund this transaction\) via \`tap\`:)\n"
DEBUG_FORCE_VERBOSE=1 tap $pubkey 2 "${script_alice}" "${script_bob}"
echo
tap_send=$(DEBUG_FORCE_VERBOSE=1 tap $pubkey 2 "${script_alice}" "${script_bob}" 2>&1)

## parse the output of `tap` to get the interesting values and pieces of the tree
int_pubkey=$(          echo ${tap_send} | grep -P -o '(?<=Internal pubkey: )[[:alnum:]]+')
script0=$(             echo ${tap_send} | grep -P -o '(?<=#0: )[[:alnum:]]+')
script1=$(             echo ${tap_send} | grep -P -o '(?<=#1: )[[:alnum:]]+')
script0_leafhash=$(    echo $(echo ${tap_send} | grep -P -o '(?<=#0 leaf hash = ).*? → [[:alnum:]]+') | grep -P -o '(?<= → )[[:alnum:]]+')
script1_leafhash=$(    echo $(echo ${tap_send} | grep -P -o '(?<=#1 leaf hash = ).*? → [[:alnum:]]+') | grep -P -o '(?<= → )[[:alnum:]]+')
branch01=$(            echo $(echo ${tap_send} | grep -P -o '(?<=Branch).*? → [[:alnum:]]+') | grep -P -o '(?<= → )[[:alnum:]]+')
tweak_value=$(         echo $(echo ${tap_send} | grep -P -o '(?<=Tweak value = Tap).*? = [[:alnum:]]+') | grep -P -o '(?<= = )[[:alnum:]]+')
tweaked_pubkey=$(      echo ${tap_send} | grep -P -o '(?<=Tweaked pubkey = )[[:alnum:]]+')
if                     echo ${tap_send} | grep -P -q '\(not even\)'; then
   tweaked_pubkey_parity=1
else
   tweaked_pubkey_parity=0
fi
send_to_addr=$(        echo ${tap_send} | grep -P -o '(?<=Resulting Bech32m address: )[[:alnum:]]+')

echo int_pubkey '              ' ${int_pubkey}
echo script0 '                 ' ${script0}
echo script1 '                 ' ${script1}
echo script0_leafhash '        ' ${script0_leafhash}
echo script1_leafhash '        ' ${script1_leafhash}
echo branch01 '                ' ${branch01}
echo tweak_value '             ' ${tweak_value}
echo tweaked_pubkey '          ' ${tweaked_pubkey}
if [[ ${tweaked_pubkey_parity} -eq 0 ]]; then
    echo tweaked_pubkey_parity '    even'
else
    echo tweaked_pubkey_parity '    odd'
fi
echo "HASH160(tweaked_pubkey)" ' ' $(hash160 ${tweaked_pubkey})
echo send_to_addr '            ' ${send_to_addr}
echo

## rename some values for convenience during the Tapscript spend

tagged_hash_alice_script=${script0_leafhash}

## send some BTC to our bech32m (taproot) send-to address

amount_to_send="0.005"
txinid=$(btc-cli sendtoaddress ${send_to_addr} ${amount_to_send})
txinraw=$(btc-cli getrawtransaction ${txinid})

printf "$(color GREEN transaction to send funds to our send-to-address:)\n"
echo amount_to_send ' ' ${amount_to_send}
echo txinid '         ' ${txinid} " ($(color ITAL transaction to send funds to send-to-addres, input to our Taproot transactions))"
echo txinraw '        ' ${txinraw}
echo

## parse the output of the sending transaction
txinjson=$(btc-cli getrawtransaction ${txinid} true)

printf "txin $(echo ${txinjson} | jq '.')\n"
echo

vout_index=$(        echo $txinjson | jq '.["vout"] | map(select(.["value"] == '${amount_to_send}')) | .[0] | .["n"]')
vout_address=$(      echo $txinjson | jq -r '.["vout"] | .['${vout_index}'] | .["scriptPubKey"] | .["address"]')
witnessprogram=$(    echo $txinjson | jq -r '.["vout"] | .['${vout_index}'] | .["scriptPubKey"] | .["asm"]')
witnessprogramhex=$( echo $txinjson | jq -r '.["vout"] | .['${vout_index}'] | .["scriptPubKey"] | .["hex"]')

echo vout_index '        ' ${vout_index} "($(color ITAL index of output that funds the send-to-address))"
echo vout_address '      ' ${vout_address} "($(color ITAL the send-to-address))"
echo witnessprogram '    ' ${witnessprogram} "($(color ITAL segwit version + tweaked pubkey))"
echo witnessprogramhex ' ' ${witnessprogramhex}
echo

## confirmation funding transaction fields match expected
if [[ ${vout_address} != ${send_to_addr} ]]; then echo "$(color RED vout_address != send_to_addr)"; fi
if [[ ${witnessprogram} != "1 ${tweaked_pubkey}" ]]; then echo "$(color RED witnessprogram[1] != tweaked_pubkey)"; fi

# CREATE A SPENDING TRANSACTION
printf "$(color GREEN create a raw spending transaction for some of the funds)\n"

amount_to_spend="0.0025"
spend_address=$(btc-cli getnewaddress '' legacy)
#--
btc-cli getaddressinfo ${spend_address}
#--
spend_address_info_json=$(btc-cli getaddressinfo ${spend_address})
spend_address_pubkey=$(echo ${spend_address_info_json} | jq -r '.["pubkey"]')
spend_address_script_pubkey=$(echo ${spend_address_info_json} | jq -r '.["scriptPubKey"]')

spend_tx=$(btc-cli createrawtransaction '[{"txid":"'${txinid}'", "vout":'${vout_index}'}]' '[{"'${spend_address}'":'${amount_to_spend}'}]')
spend_tx_json=$(btc-cli decoderawtransaction ${spend_tx})

printf "spend_address info $(echo ${spend_address_info_json} | jq '.')\n"
echo

echo amount_to_spend '               ' ${amount_to_spend}
echo spend_address '                 ' ${spend_address}
echo spend_address_pubkey '          ' ${spend_address_pubkey}
echo "HASH160(spend_address_pubkey)" ' ' $(hash160 ${spend_address_pubkey})
echo spend_address_script_pubkey '   ' ${spend_address_script_pubkey}
echo "HASH160(...script_pubkey)    " ' ' $(hash160 ${spend_address_script_pubkey})
echo spend_tx '                      ' ${spend_tx}
echo
printf "spend_tx $(echo ${spend_tx_json} | jq '.')\n"
echo

# SIGN THIS TRANSACTION AS A DIRECT TAPROOT SPEND BY PROVIDING THE (INTERNAL) PRIVATE KEY
printf "$(color GREEN create signed direct spend transaction \(\"tap_directspend\"\) via \`tap\`)\n"

printf "${YELLOW} \`tap\` output:\n"
DEBUG_FORCE_VERBOSE=1 tap --privkey=${privkey} --tx=${spend_tx} --txin=${txinraw} ${pubkey} 2 "${script_alice}" "${script_bob}"
printf "$(color YELLOW)\n"
tap_directspend=$(DEBUG_FORCE_VERBOSE=1 tap --privkey=${privkey} --tx=${spend_tx} --txin=${txinraw} ${pubkey} 2 "${script_alice}" "${script_bob}" 2>&1)

## parse the output of `tap` to get the interesting values
type_directspend=$(            echo ${tap_directspend} | grep -P -o '(?<=spend arguments; )[[:alnum:]]+')
tweaked_pubkey_directspend=$(  echo ${tap_directspend} | grep -P -o '(?<=Tweaked pubkey = )[[:alnum:]]+')
if                             echo ${tap_directspend} | grep -P -q '\(not even\)'; then
   tweaked_pubkey_parity_directspend=1
else
   tweaked_pubkey_parity_directspend=0
fi
tweaked_privkey_directspend=$( echo ${tap_directspend} | grep -P -o '(?<=tweaked privkey -> )[[:alnum:]]+')
if                             echo ${tap_directspend} | grep -P -q '\(pk_parity = 1\)'; then
   tweaked_privkey_parity_directspend=1
else
   tweaked_privkey_parity_directspend=0
fi
sighash_directspend=$(         echo ${tap_directspend} | grep -P -o '(?<=sighash: )[[:alnum:]]+')
sig_directspend=$(             echo ${tap_directspend} | grep -P -o '(?<=signature: )[[:alnum:]]+')
txraw_directspend=$(           echo ${tap_directspend} | grep -P -o '(?<=Resulting transaction: )[[:alnum:]]+')
txraw_directspend_json=$(btc-cli decoderawtransaction ${txraw_directspend})
witnessprogram_directspend=$(  echo ${txraw_directspend_json} | jq -r '.["vout"] | .[0] | .["scriptPubKey"] | .["asm"]' | cut -b 3-)

echo type_directspend '                    ' ${type_directspend}
echo tweaked_pubkey_directspend '          ' ${tweaked_pubkey_directspend}
if [[ ${tweaked_pubkey_parity_directspend} -eq 0 ]]; then
    echo tweaked_pubkey_parity_directspend  '    even'
else
    echo tweaked_pubkey_parity_directspend  '    odd'
fi
echo HASH160\(tweaked_pubkey_directspend\) ' ' $(hash160 ${tweaked_pubkey_directspend})
echo tweaked_privkey_directspend '         ' ${tweaked_privkey_directspend}
if [[ ${tweaked_privkey_parity_directspend} -eq 0 ]]; then
    echo tweaked_privkey_parity_directspend '   even'
else
    echo tweaked_privkey_parity_directspend '   odd'
fi
echo witnessprogram_directspend '          ' ${witnessprogram_directspend}
echo sig_directspend '                     ' ${sig_directspend}
echo txraw_directspend '                   ' ${txraw_directspend}
echo

printf "txraw_directspend decoded: $(echo ${txraw_directspend_json} | jq '.')\n"
echo


## see if that signed transaction would be accepted for the mempool
printf "$(color GREEN test acceptance via \`testmempoolaccept\`:)\n"
testaccept_directspend=$(btc-cli testmempoolaccept '["'${txraw_directspend}'"]')
accepted_directspend=$(echo ${testaccept_directspend} | jq '.[0] | .["allowed"]')
echo accepted_directspend? ' ' ${accepted_directspend}
echo

printf "testaccept_directspend: $(echo ${testaccept_directspend} | jq '.')\n"
echo

return

# SIGN (SAME) TRANSACTION AS A TAPSCRIPT SPEND OF BOB'S OUTPUT (WITH BOB'S PRIVATE KEY BUT NOT (INTERNAL) PRIVATE KEY)

printf "tap_bobspend (signed tapscript \"Bob\s spend\" transaction) via \`tap\`\n"
DEBUG_FORCE_VERBOSE=1 tap -k${bob_privkey} --tx=${spend_tx} --txin=${txinraw} ${pubkey} 2 "${script_alice}" "${script_bob}" 1 ${preimage}
echo
tap_bobspend=$(DEBUG_FORCE_VERBOSE=1 tap -k${bob_privkey} --tx=${spend_tx} --txin=${txinraw} ${pubkey} 2 "${script_alice}" "${script_bob}" 1 ${preimage} 2>&1)

## parse the output of tap` to get the interesting values`

ts_int_pubkey=$(               echo ${tap_bobspend} | grep -P -o '(?<=Internal pubkey: )[[:alnum:]]+')
ts_type=$(                     echo ${tap_bobspend} | grep -P -o '(?<=spend arguments; )[[:alnum:]]+')
ts_script0=$(                  echo ${tap_bobspend} | grep -P -o '(?<=#0: )[[:alnum:]]+')
ts_script1=$(                  echo ${tap_bobspend} | grep -P -o '(?<=#1: )[[:alnum:]]+')
ts_script0_leafhash=$(         echo $(echo ${tap_bobspend} | grep -P -o '(?<=#0 leaf hash = ).*? → [[:alnum:]]+') | grep -P -o '(?<= → )[[:alnum:]]+')
ts_script1_leafhash=$(         echo $(echo ${tap_bobspend} | grep -P -o '(?<=#1 leaf hash = ).*? → [[:alnum:]]+') | grep -P -o '(?<= → )[[:alnum:]]+')
ts_branch01=$(                 echo $(echo ${tap_bobspend} | grep -P -o '(?<=Branch).*? → [[:alnum:]]+') | grep -P -o '(?<= → )[[:alnum:]]+')
ts_tweak_value=$(              echo $(echo ${tap_bobspend} | grep -P -o '(?<=Tweak value = Tap).*? = [[:alnum:]]+') | grep -P -o '(?<= = )[[:alnum:]]+')
ts_tweaked_pubkey=$(           echo ${tap_bobspend} | grep -P -o '(?<=Tweaked pubkey = )[[:alnum:]]+')
ts_send_to_addr=$(             echo ${tap_bobspend} | grep -P -o '(?<=Resulting Bech32m address: )[[:alnum:]]+')
ts_controlobject_bobspend=$(   echo ${tap_bobspend} | grep -P -o '(?<=Final control object = )[[:alnum:]]+')
ts_spendingwitness_bobspend=$( echo ${tap_bobspend} | grep -P -o '(?<=Tapscript spending witness: )\[.*?\]')
ts_sig_bobspend=$(             echo ${tap_bobspend} | grep -P -o '(?<=signature: )[[:alnum:]]+')
ts_txraw_bobspend=$(           echo ${tap_bobspend} | grep -P -o '(?<=Resulting transaction: )[[:alnum:]]+')

echo tap_bobspend via \`tap\`:
echo ${tap_bobspend}
echo

echo ts_type '                     ' ${ts_type}
echo ts_int_pubkey '               ' ${ts_int_pubkey}
echo ts_script0 '                  ' ${ts_script0}
echo ts_script1 '                  ' ${ts_script1}
echo ts_script0_leafhash '         ' ${ts_script0_leafhash}
echo ts_script1_leafhash '         ' ${ts_script1_leafhash}
echo ts_branch01 '                 ' ${ts_branch01}
echo ts_tweak_value '              ' ${ts_tweak_value}
echo ts_tweaked_pubkey '           ' ${ts_tweaked_pubkey}
echo ts_send_to_addr '             ' ${ts_send_to_addr}
echo ts_controlobject_bobspend '   ' ${ts_controlobject_bobspend}
echo ts_spendingwitness_bobspend ' ' ${ts_spendingwitness_bobspend}
echo ts_sig_bobspend '             ' ${ts_sig_bobspend}
echo ts_txraw_bobspend '           ' ${ts_txraw_bobspend}
echo
echo ts_xraw_bobspend decoded:
btc-cli decoderawtransaction ${ts_txraw_bobspend}
echo

## see if that signed transaction can be sent
echo test send via \`sendrawtransaction\`:
ts_txid_bobspend=$(btc-cli sendrawtransaction ${ts_txraw_bobspend} 2>&1)

if [[ "${ts_txid_bobspend}" =~ "error code" ]]; then
  echo accepted Tapscript spend? false;
  echo spend result: ${ts_txid_bobspend};
else
  ts_sentrawtx_bobspend=$(btc-cli getrawtransaction ${ts_txid_bobspend} 1);
  echo "accepted Tapscript spend? true";
  echo txid_bobspend '           ' ${ts_txid_bobspend};
  printf "sentrawtx_bobspend $(echo ${ts_sentrawtx_bobspend} | jq '.')\n";
fi
echo

# btc-kill

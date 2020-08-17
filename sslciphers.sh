#!/usr/bin/env bash
ciphers2=$(openssl ciphers -ssl2 'ALL:eNULL' | sed -e 's/:/ /g')
ciphers3=$(openssl ciphers -ssl3 'ALL:eNULL' | sed -e 's/:/ /g')
cipherst1=$(openssl ciphers -tls1 'ALL:eNULL' | sed -e 's/:/ /g')
cipherst11=$(openssl ciphers -tls1.1 'ALL:eNULL' | sed -e 's/:/ /g')
cipherst12=$(openssl ciphers -tls1.2 'ALL:eNULL' | sed -e 's/:/ /g')

SSL2="SSL2("
for cipher in ${ciphers2[@]}
do
result=$(echo -n | openssl s_client -ssl2 -cipher "$cipher" -connect $1:$2 2>&1)
if [[ "$result" =~ "Cipher is ${cipher}" ]] ; then
  SSL2="${SSL2}${cipher}:"
fi
done
SSL2=$(echo "${SSL2})" | sed -e 's/:)/)/g')

SSL3="SSL3("
for cipher in ${ciphers3[@]}
do
result=$(echo -n | openssl s_client -ssl3 -cipher "$cipher" -connect $1:$2 2>&1)
if [[ "$result" =~ "Cipher is ${cipher}" ]] ; then
  SSL3="${SSL3}${cipher}:"
fi
done
SSL3=$(echo "${SSL3})" | sed -e 's/:)/)/g')
TLS1="TLS1("
for cipher in ${cipherst1[@]}
do
result=$(echo -n | openssl s_client -tls1 -cipher "$cipher" -connect $1:$2 2>&1)
if [[ "$result" =~ "Cipher is ${cipher}" ]] ; then
  TLS1="${TLS1}${cipher}:"
fi
done
TLS1=$(echo "${TLS1})" | sed -e 's/:)/)/g')

TLS11="TLS1.1("
for cipher in ${cipherst11[@]}
do
result=$(echo -n | openssl s_client -tls1_1 -cipher "$cipher" -connect $1:$2 2>&1)
if [[ "$result" =~ "Cipher is ${cipher}" ]] ; then
  TLS11="${TLS11}${cipher}:"
fi
done
TLS11=$(echo "${TLS11})" | sed -e 's/:)/)/g')

TLS12="TLS1.2("
for cipher in ${cipherst12[@]}
do
result=$(echo -n | openssl s_client -tls1_2 -cipher "$cipher" -connect $1:$2 2>&1)
if [[ "$result" =~ "Cipher is ${cipher}" ]] ; then
  TLS12="${TLS12}${cipher}:"
fi
done
TLS12=$(echo "${TLS12})" | sed -e 's/:)/)/g')

echo "$1,\n$SSL2 ,\n$SSL3 ,\n$TLS1 ,\n$TLS11 , \n$TLS12 \n";

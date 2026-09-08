window.ATTACK = {
  "secret_plaintext": "FLAG{h4rv35t_n0w_d3crypt_l4t3r}",
  "before": {
    "algorithm": "rsa-toy",
    "label": "Classical RSA",
    "family": "integer factoring",
    "quantum_vulnerable": true,
    "n": 33,
    "e": 3,
    "bits": 6,
    "note": "6-bit teaching example; distinct public/private exponents",
    "ciphertext": "{\"n\":33,\"len\":31,\"c\":[31,13,23,24,16,30,30,14,21,31,11,24,14,9,32,27,18,23,26,26,8,32,26,7,7,29,31,21,7,31,16,6,23,22,28,0,16,19,31,8,5,4,7,30,15,10,21,1,4]}",
    "ciphertext_bytes": 157,
    "attack": {
      "applicable": true,
      "success": true,
      "algorithm": "rsa-toy",
      "N": 33,
      "a": 13,
      "measured_c": 3686,
      "M": 4096,
      "counting_qubits": 12,
      "work_qubits": 6,
      "period": 10,
      "half_exp": 10,
      "peaks": [
        [
          0,
          0.10000014305114746
        ],
        [
          409,
          0.025457250469014616
        ],
        [
          410,
          0.05727873373184694
        ],
        [
          819,
          0.08751413288445167
        ],
        [
          820,
          0.00546973898836102
        ],
        [
          1228,
          0.00546973898836102
        ],
        [
          1229,
          0.08751413288445167
        ],
        [
          1638,
          0.05727873373184694
        ],
        [
          1639,
          0.025457250469014626
        ],
        [
          2048,
          0.10000014305114746
        ],
        [
          2457,
          0.025457250469014616
        ],
        [
          2458,
          0.05727873373184694
        ],
        [
          2867,
          0.08751413288445167
        ],
        [
          3277,
          0.08751413288445167
        ],
        [
          3686,
          0.05727873373184694
        ],
        [
          3687,
          0.025457250469014626
        ]
      ],
      "factors": [
        3,
        11
      ],
      "recovered_d": 7,
      "attempts": 2,
      "revealed": "FLAG{h4rv35t_n0w_d3crypt_l4t3r}",
      "resource_estimate": {
        "modulus_bits": 6,
        "counting_qubits": 12,
        "work_qubits": 6,
        "logical_qubits_approx": 20,
        "statevector_amplitudes": "2^18"
      }
    }
  },
  "after": {
    "algorithm": "ml-kem-768",
    "label": "ML-KEM-768 (FIPS 203)",
    "family": "Module-LWE (lattice)",
    "quantum_vulnerable": false,
    "public_bytes": 1184,
    "private_bytes": 2400,
    "ciphertext_preview": "{\"format\":\"pqc-lab-v2\",\"level\":\"768\",\"kem_ct\":\"0SuLXUqnFuOFVP/b9ZZxd6xCpCv3XXwUu",
    "ciphertext_bytes": 1602,
    "attack": {
      "applicable": false,
      "success": false,
      "algorithm": "ml-kem-768",
      "probe": {
        "public_key_type": "MLKEMPublicKey",
        "integer_modulus_found": false,
        "public_key_bytes": 1184
      },
      "reason": "Not applicable: this implementation attacks RSA factoring keys. ML-KEM is a lattice-based key encapsulation mechanism. No Shor circuit was run against it, and this dispatch result is not a proof of post-quantum security."
    },
    "opened_with_key": true
  },
  "resources": {
    "toy": {
      "modulus_bits": 6,
      "counting_qubits": 12,
      "work_qubits": 6,
      "logical_qubits_approx": 20,
      "statevector_amplitudes": "2^18"
    },
    "rsa2048": {
      "modulus_bits": 2048,
      "counting_qubits": 4096,
      "work_qubits": 2048,
      "logical_qubits_approx": 6146,
      "statevector_amplitudes": "2^6144"
    }
  },
  "migration": {
    "application_code_changes": 0,
    "registry_line": "register(\"ml-kem-768\", _mlkem_factory(\"768\"))",
    "note": "For this application, select a new backend and generate new keys; reseal data. Existing ciphertext is not migrated automatically."
  }
};

class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.28"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.28/ciphervault-v1.0.28-aarch64-apple-darwin.tar.gz"
      sha256 "8f348c5c8293b19e2d1b0b8206929f9335818ec1dfa2b3388415e6c06b6ee4b5"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.28/ciphervault-v1.0.28-x86_64-apple-darwin.tar.gz"
      sha256 "1320774d127c94b6d9533f2ff88537dd0727d5a6da8e0b5d93e4a009c8f4d998"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.28/ciphervault-v1.0.28-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "9045a0bb844563d1b63818c1014816587b5c1dbe049be6d80806e63bab6aa43b"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.28/ciphervault-v1.0.28-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0a171697ce62afe7568bb386da33c2b25fa1f4beb89a835f5e47cfe34dfc5320"
    end
  end

  def install
    bin.install "bin/ciphervault"
    bin.install "bin/ciphervault-operator"
    bin.install "bin/ciphervault-agent"
    bin.install "bin/ciphervault-maintenance"

    if Dir.exist?("config")
      (etc/"ciphervault").install Dir["config/*"]
    end
  end

  def caveats
    <<~EOS
      Quick Start:
        ciphervault init
        ciphervault track .env
        ciphervault push -m "Initial commit"
        ciphervault diff
        ciphervault run -- npm start
        ciphervault peers
    EOS
  end

  test do
    assert_match "Decentralized, encrypted version control", shell_output("#{bin}/ciphervault --help")
  end
end

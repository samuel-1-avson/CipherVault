class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.26"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.26/ciphervault-v1.0.26-aarch64-apple-darwin.tar.gz"
      sha256 "2fb38c80e4a055f76c05cbb6a8327cb845742b9cc46927032b0b77d09bc0c1fe"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.26/ciphervault-v1.0.26-x86_64-apple-darwin.tar.gz"
      sha256 "7252a5bf122e4a03ee1b9a81060223f8d1e8421fab4de8a3bea0eefb2f9e4ea3"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.26/ciphervault-v1.0.26-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "70e87aa404c18bbfacaa0dbf6b1281aef874dbdb17bdf4caa6b0097ecaa8bd3b"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.26/ciphervault-v1.0.26-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "314f70fecff802c81a962c58b1f81a3158678e76f071ade6c83b17809ebfa9df"
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

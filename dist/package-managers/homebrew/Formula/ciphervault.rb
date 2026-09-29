class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.24"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.24/ciphervault-v1.0.24-aarch64-apple-darwin.tar.gz"
      sha256 "3c9fba78b2443aac87a0fd73b83b92e5515fd5e08e9da76b8b9c90d977cce9bf"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.24/ciphervault-v1.0.24-x86_64-apple-darwin.tar.gz"
      sha256 "35eb944cdf53668b2cbd3f4295e964a93e8dd3bf601113b0bd317645b67b82aa"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.24/ciphervault-v1.0.24-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "359bdc40b34a06d8d72a966ece20112b7c927e2c6528934dae791617e9b0af11"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.24/ciphervault-v1.0.24-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "54014513a794e4cc7494cf87fb237c52e92798d8a6d2e0a46509f73395527356"
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

class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.25"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.25/ciphervault-v1.0.25-aarch64-apple-darwin.tar.gz"
      sha256 "341242bb0c4a4a3af645af954dd8969ee73c988288f59ab880251477e5d8018f"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.25/ciphervault-v1.0.25-x86_64-apple-darwin.tar.gz"
      sha256 "2fe3bb734bb252243975fb3ca0c20a90d98e695a6aabfc9518be004d98436d84"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.25/ciphervault-v1.0.25-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "57ea674802572421837c03384717633fd00cc56c1661da1a7be23be3a9d1b7db"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.25/ciphervault-v1.0.25-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "f68fba1d772ab9fe0d554e3c5cdbba4163ce310a65c90bfd23be20888c71ab29"
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

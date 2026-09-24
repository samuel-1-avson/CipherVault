class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.14"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.14/ciphervault-v1.0.14-aarch64-apple-darwin.tar.gz"
      sha256 "6efbf5e7f9e1ebcb57474c1214ea954649976021601b538d90cee3dedb8ca483"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.14/ciphervault-v1.0.14-x86_64-apple-darwin.tar.gz"
      sha256 "0f0d55ee4a070a97a41d2ab81ff4b695ffb25cfe353c8b61745a9cdeb453f380"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.14/ciphervault-v1.0.14-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "29220505d12ca54248c9ddebcce719a477f1a0da67932a8b288b897d52e44242"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.14/ciphervault-v1.0.14-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "2b9557dee7388f613addb4f8521960bbe120b451d46598b9afa6e170b56e1577"
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

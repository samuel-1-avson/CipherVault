class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.18"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.18/ciphervault-v1.0.18-aarch64-apple-darwin.tar.gz"
      sha256 "01cdb8c93872233348bbbf91fd162a6c0fc53a2d63e3f48042849439b9d7b179"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.18/ciphervault-v1.0.18-x86_64-apple-darwin.tar.gz"
      sha256 "19c4b78f7daef7ca9dda603183a177db5a9edafae3d7efd3d84bd5aebb6b6b59"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.18/ciphervault-v1.0.18-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "7bdc744d5557a04d9db4cf61cd9a52059dbbaa1d5425c82d88e0c8eb8fc6018a"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.18/ciphervault-v1.0.18-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "ebe8d8cbb15888f46a7bcc790e70cc1bbc9dc84f769eb92a18c7f62f62d0f7ee"
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

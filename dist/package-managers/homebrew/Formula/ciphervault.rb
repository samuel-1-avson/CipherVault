class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.22"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.22/ciphervault-v1.0.22-aarch64-apple-darwin.tar.gz"
      sha256 "962828f8f9c6e121d6d542d25a9a7c487e4bb222cd28847fd57e1a71c9d54f9f"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.22/ciphervault-v1.0.22-x86_64-apple-darwin.tar.gz"
      sha256 "8a3f6d279b07ee1b6de2a8fb42c2f47aa78776771d51d1f5920d2283cdb86133"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.22/ciphervault-v1.0.22-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "b377c6dae04a8e1a61a030c8e8be39211a36db8427b848bcbebfda161f31e78d"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.22/ciphervault-v1.0.22-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "3d474938540ee37eba379603c4e58c096180b2c4646577defa69057900509689"
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

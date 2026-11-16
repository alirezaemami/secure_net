// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "SecureNet",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "securenetd", targets: ["securenetd"]),
        .executable(name: "securenetctl", targets: ["securenetctl"]),
        .executable(name: "SecureNetMenu", targets: ["SecureNetMenu"]),
    ],
    targets: [
        .target(name: "SecureNetCore"),
        .executableTarget(name: "securenetd", dependencies: ["SecureNetCore"]),
        .executableTarget(name: "securenetctl", dependencies: ["SecureNetCore"]),
        .executableTarget(name: "SecureNetMenu", dependencies: ["SecureNetCore"]),
        .testTarget(name: "SecureNetCoreTests", dependencies: ["SecureNetCore"]),
    ]
)

import AVFoundation
import SwiftUI
import UIKit

/// Live camera feed plus a single QR-payload callback. Stops the session
/// after the first decode, so callers don't receive duplicates.
struct QRScannerView: UIViewControllerRepresentable {
    let onScanned: @MainActor (String) -> Void
    let onCancel: @MainActor () -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let vc = ScannerViewController()
        vc.onScanned = onScanned
        vc.onCancel = onCancel
        return vc
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {}
}

final class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onScanned: (@MainActor (String) -> Void)?
    var onCancel: (@MainActor () -> Void)?

    private let session = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    /// True once the capture session has been built. Gates
    /// `viewDidAppear` from calling `startRunning()` on a session with
    /// no input — the camera-unavailable states never reach that.
    private var sessionReady = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        let cancel = UIButton(type: .system)
        cancel.setTitle("Cancel", for: .normal)
        cancel.tintColor = .white
        cancel.titleLabel?.font = .preferredFont(forTextStyle: .body)
        cancel.translatesAutoresizingMaskIntoConstraints = false
        cancel.addAction(UIAction { [weak self] _ in
            Task { @MainActor in self?.onCancel?() }
        }, for: .touchUpInside)
        view.addSubview(cancel)
        NSLayoutConstraint.activate([
            cancel.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 16),
            cancel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
        ])

        // Camera-permission gate. A denied / restricted camera (the
        // user tapped "Don't Allow", or MDM / Screen Time blocks it)
        // must never leave the user staring at a silent black sheet —
        // every unavailable state gets a legible explanation. The
        // first-launch prompt also fires here, in a controlled moment,
        // rather than from deep inside `configureSession`.
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            startConfiguredSession()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    guard let self else { return }
                    if granted {
                        self.startConfiguredSession()
                    } else {
                        self.showCameraUnavailable(.denied)
                    }
                }
            }
        case .denied, .restricted:
            showCameraUnavailable(.denied)
        @unknown default:
            showCameraUnavailable(.denied)
        }
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard sessionReady, !session.isRunning else { return }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.session.startRunning()
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning {
            session.stopRunning()
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    /// Reason a camera feed could not be shown — drives the
    /// explanatory-view copy.
    private enum CameraUnavailableReason {
        /// Permission denied or restricted by the user / MDM / Screen
        /// Time. Recoverable via Settings.
        case denied
        /// Permission was granted but no usable capture device exists
        /// (no camera, or it could not be added to the session).
        case noDevice
    }

    /// Builds the capture session and, on success, starts it on next
    /// `viewDidAppear`. On any failure renders the explanatory view so
    /// the user is never left with an unexplained black sheet.
    private func startConfiguredSession() {
        guard configureSession() else {
            showCameraUnavailable(.noDevice)
            return
        }
        sessionReady = true
        // `viewDidAppear` may have already fired (permission prompt is
        // async); kick the session if so.
        if isViewLoaded, view.window != nil, !session.isRunning {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.session.startRunning()
            }
        }
    }

    /// Renders an in-sheet explanation with an "Open Settings" deep
    /// link and a note that invite-link pairing is an alternative.
    /// Replaces the silent black rectangle for every camera-
    /// unavailable state.
    private func showCameraUnavailable(_ reason: CameraUnavailableReason) {
        let title = UILabel()
        title.text = "Camera unavailable"
        title.font = .preferredFont(forTextStyle: .title2)
        title.textColor = .white
        title.textAlignment = .center
        title.numberOfLines = 0

        let detail = UILabel()
        switch reason {
        case .denied:
            detail.text = "Pizzini needs camera access to scan a contact's QR code. "
                + "Enable it in Settings, or pair using an invite link instead."
        case .noDevice:
            detail.text = "No usable camera was found on this device. "
                + "You can still pair using an invite link instead."
        }
        detail.font = .preferredFont(forTextStyle: .body)
        detail.textColor = .white
        detail.textAlignment = .center
        detail.numberOfLines = 0

        let stack = UIStackView(arrangedSubviews: [title, detail])
        stack.axis = .vertical
        stack.spacing = 12
        stack.alignment = .fill
        stack.translatesAutoresizingMaskIntoConstraints = false

        // The Settings deep link only helps when the camera was
        // explicitly denied/restricted — a missing camera can't be
        // granted in Settings.
        if reason == .denied {
            let openSettings = UIButton(type: .system)
            openSettings.setTitle("Open Settings", for: .normal)
            openSettings.titleLabel?.font = .preferredFont(forTextStyle: .headline)
            openSettings.addAction(UIAction { _ in
                guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
                UIApplication.shared.open(url)
            }, for: .touchUpInside)
            stack.addArrangedSubview(openSettings)
        }

        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 32),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -32),
        ])
    }

    /// Builds the capture session. Returns `false` — without mutating
    /// any session state the caller relies on — when no usable capture
    /// device exists, so the caller can surface a legible explanation
    /// rather than a black sheet. Assumes camera permission is already
    /// authorized.
    private func configureSession() -> Bool {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else {
            return false
        }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return false }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: DispatchQueue.main)
        output.metadataObjectTypes = [.qr]

        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.bounds
        view.layer.insertSublayer(layer, at: 0)
        self.previewLayer = layer
        return true
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard
            let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
            let value = object.stringValue
        else { return }
        session.stopRunning()
        Task { @MainActor in onScanned?(value) }
    }
}

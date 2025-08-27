/*
 * ExpandingTextEditor.swift
 * -------------------------
 * UIKit backed multi-line text editor that automatically grows to fit its
 * content up to a configurable maximum height. Used as the compose field in
 * ChatView so users can type messages of arbitrary length without the input
 * obstructing the conversation.
 *
 * Usage:
 * ``ExpandingTextEditor(text: $draft, height: $height)``
 * Place the returned view in a container and constrain its frame using the
 * provided ``height`` binding. The control reports its intrinsic content height
 * whenever the text changes.
 */
import SwiftUI

/// Multi-line text input built on ``UITextView`` that expands with its content.
///
/// The view keeps ``text`` synchronized with the underlying ``UITextView`` and
/// reports its current height through ``height`` so that the parent can resize
/// the view. Height is clamped to ``maxHeight`` to prevent the input from
/// growing beyond a reasonable size and hiding recent chat history.
struct ExpandingTextEditor: UIViewRepresentable {
    /// Text bound to the underlying ``UITextView``.
    @Binding var text: String
    /// Height of the editor reported back to the caller. Updated whenever the
    /// content size changes.
    @Binding var height: CGFloat
    /// Maximum allowed height before the view becomes scrollable.
    var maxHeight: CGFloat = 120

    func makeUIView(context: Context) -> UITextView {
        let view = UITextView()
        // Disable internal scrolling so the surrounding SwiftUI layout drives
        // the height. The delegate will update ``height`` as the content grows.
        view.isScrollEnabled = false
        view.font = UIFont.preferredFont(forTextStyle: .body)
        view.delegate = context.coordinator
        view.backgroundColor = .clear
        // Allow the view to shrink horizontally when placed in tight layouts.
        view.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return view
    }

    func updateUIView(_ uiView: UITextView, context: Context) {
        // Keep UIKit control in sync with the bound text.
        if uiView.text != text {
            uiView.text = text
        }
        // Defer height calculation to the next runloop so ``contentSize`` is
        // updated. This avoids layout warnings from synchronous mutations.
        DispatchQueue.main.async {
            let targetSize = CGSize(width: uiView.bounds.width,
                                    height: .greatestFiniteMagnitude)
            let fitting = uiView.sizeThatFits(targetSize)
            // Clamp to ``maxHeight`` so the field does not overtake the screen.
            let newHeight = min(maxHeight, fitting.height)
            if abs(height - newHeight) > 0.5 {
                height = newHeight
            }
        }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(text: $text)
    }

    /// Delegate bridging text changes from ``UITextView`` back to SwiftUI.
    final class Coordinator: NSObject, UITextViewDelegate {
        /// Binding to the external ``text`` value.
        var text: Binding<String>
        init(text: Binding<String>) { self.text = text }
        func textViewDidChange(_ textView: UITextView) {
            // Propagate edits to the SwiftUI binding.
            text.wrappedValue = textView.text
        }
    }
}

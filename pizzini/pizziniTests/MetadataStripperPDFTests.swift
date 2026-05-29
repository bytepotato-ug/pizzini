import Foundation
import Testing
import PDFKit
import UIKit
@testable import pizzini

/// PZ-L5: PDFs now get their document-info dictionary stripped before
/// send (operator decision: strip what we cleanly can, keep the
/// attach-time warning since XMP/annotations may remain). These tests
/// build a PDF with author/creator set, strip it, and byte-search the
/// WHOLE output for those strings — so the assertion fails if the value
/// survives anywhere (Info dict OR an XMP duplicate), giving an honest
/// empirical read on effectiveness. Runs on the sim (PDFKit + UIKit).
@Suite("PZ-L5 PDF metadata strip")
struct MetadataStripperPDFTests {
    private func makePDFWithAuthor(_ author: String, creator: String) -> Data {
        let img = UIGraphicsImageRenderer(size: CGSize(width: 10, height: 10)).image { ctx in
            UIColor.gray.setFill()
            ctx.fill(CGRect(x: 0, y: 0, width: 10, height: 10))
        }
        let doc = PDFDocument()
        if let page = PDFPage(image: img) {
            doc.insert(page, at: 0)
        }
        doc.documentAttributes = [
            PDFDocumentAttribute.authorAttribute: author,
            PDFDocumentAttribute.creatorAttribute: creator,
        ]
        return doc.dataRepresentation() ?? Data()
    }

    private func bytesContain(_ data: Data, _ marker: String) -> Bool {
        String(decoding: data, as: UTF8.self).contains(marker)
    }

    @Test("strip clears the PDF document-info author/creator")
    func docInfoCleared() throws {
        let author = "SECRET-PDF-AUTHOR-9c2b"
        let creator = "SECRET-CREATOR-app-4d1e"
        let original = makePDFWithAuthor(author, creator: creator)
        // Precondition: the fixture really embeds the author in the bytes
        // (else the test would pass vacuously).
        #expect(bytesContain(original, author), "fixture must embed the author")

        let stripped = try MetadataStripper.stripped(
            original, filename: "doc.pdf", mimeType: "application/pdf"
        )
        // The document-info dictionary is cleared.
        let strippedDoc = try #require(PDFDocument(data: stripped))
        let attrs = strippedDoc.documentAttributes ?? [:]
        #expect(attrs[PDFDocumentAttribute.authorAttribute] == nil)
        #expect(attrs[PDFDocumentAttribute.creatorAttribute] == nil)
        // And neither string survives anywhere in the output bytes.
        #expect(!bytesContain(stripped, author), "author must not survive in the bytes")
        #expect(!bytesContain(stripped, creator), "creator must not survive in the bytes")
        // Still a valid one-page PDF.
        #expect(strippedDoc.pageCount == 1)
    }

    @Test("bytes that aren't a PDF (mislabeled .pdf) pass through unchanged")
    func nonPDFPassesThrough() throws {
        let garbage = Data("this is definitely not a pdf".utf8)
        let out = try MetadataStripper.stripped(
            garbage, filename: "x.pdf", mimeType: "application/pdf"
        )
        #expect(out == garbage)
    }
}

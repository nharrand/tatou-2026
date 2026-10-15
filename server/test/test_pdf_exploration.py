
# fitz is the python import name used by pymuådf, a library for reading, creating, and modifying pdf documents
import fitz

# import the projects explore_pdf() function from the watermarking_utils module.

# this function takes pdf bytes and returns a dictionary describing the pdfs structure

from watermarking_utils import explore_pdf


def test_explore_pdf_identifies_all_pages():

# create a pdf in memory

# create a new, empty pdf document, contains zero pages

    doc = fitz.open()

    # range(3) produces three values 0,1,2 so the loop executes three times and creates three new blank pages to the pdf
    for _ in range(3):
        doc.new_page()
        
    
    # convert the pdf into bytes
    # converts the entire pdf into a sequence of bytes
    pdf_bytes = doc.tobytes()
    
    # to avoid errors or other problems, always close the pdf after u are finished with it
    #closes pymupdf
    doc.close()
    
    # call the pdf explore/inspect funtion with the bytes from the newly creates pdf
    
    result = explore_pdf(pdf_bytes)
    
    # verify information
    
    # verify that the returned dictionary is a document
    assert result["type"] == "Document"
    # check that the reported size matches the actual pdf data.
    assert result["size"] == len(pdf_bytes)
    
    
    # extract all page nodes:
    
    pages = []
    
    

    for node in result["children"]:
        if node["type"] == "Page" and node["id"].startswith("page:"):
            pages.append(node)
            
    
    # verify that all the pages were found
    
    assert len(pages) == 3
    
    # verify the page ids
    
    assert [page["id"] for page in pages] == [
    "page:0000",
    "page:0001",
    "page:0002",
    ]
    
    
    # verify that the function is deterministic
    
    # a function that produces the same output for the same input in called deterministic
    
    assert explore_pdf(pdf_bytes) == result
    
    
    

def test_explore_pdf_fallback_parser():
    # deliberately incomplete pdf-like data
    # pymupdf should reject it, triggering the fallback parser
    
    # missing important parts of a complete pdf document 
    
    # the tests should assume that pymupdf rejects these bytes
    pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Page >>\n"
        b"endobj\n"
    )

    # passes the bytes to the pdf inspection function within tatou
    
    # it should??? i hope, return useful structural information even though the document is incomplete
    result = explore_pdf(pdf_bytes)

    assert result["type"] == "Document"
    assert result["size"] == len(pdf_bytes)

    # check that the fallback parser identified the objects
    object_nodes = [
        node for node in result["children"]
        if node["id"].startswith("obj:")
    ]

    assert len(object_nodes) == 2
    assert object_nodes[0]["type"] == "Catalog"
    assert object_nodes[1]["type"] == "Page"

    # results should be deterministic
    assert explore_pdf(pdf_bytes) == result

    
    
    
    
    



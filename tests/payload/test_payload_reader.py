from wapitiCore.attack.attack import PayloadReader, PayloadType


def test_payload_reader():
    reader = PayloadReader({"timeout": 5, "external_endpoint": "http://perdu.com/"})
    payload, flags = reader.process_line("[TAB]\\0[EXTERNAL_ENDPOINT][LF][TIME][TIMEOUT] \n ")
    assert payload == "\t\0http://perdu.com/\n6"
    assert flags.type == PayloadType.time

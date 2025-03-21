from unittest.mock import AsyncMock

import httpx
import respx
import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_printer import ModulePrinter


@pytest.mark.asyncio
@respx.mock
async def test_no_printer_detected_via_html():
    respx.get("http://printer.local/").mock(
        return_value=httpx.Response(
            200,
            headers={},
            content="<html><head><title>Unknown Device</title></head><body>No Printer Here</body></html>"
        )
    )
    respx.get(url__regex=r"http://printer.local/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://printer.local/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://printer.local/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModulePrinter(crawler, persister, options, crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 0

@pytest.mark.asyncio
@respx.mock
async def test_hp_model_detection_from_html():
    # Mock the root endpoint with no Server header but model info in HTML
    respx.get("http://printer.local/").mock(
        return_value=httpx.Response(
            200,
            headers={},  # No Server header
            content="""
                <html>
                    <head><title>Welcome</title></head>
                    <body>
                        <p>Welcome to your printer!</p>
                        <p>Model: HP LaserJet Pro MFP M428fdw</p>
                    </body>
                </html>
            """
        )
    )

    # Block other endpoints with 404
    respx.get(url__regex=r"http://printer.local/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://printer.local/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://printer.local/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModulePrinter(crawler, persister, options, crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "HP LaserJet Pro MFP M428fdw", "versions": [""], "categories": ["Network Equipment"], "groups": ["Printers"]}'
        )
        assert persister.add_payload.call_args_list[0][1]["module"] == "printer"

@pytest.mark.asyncio
@respx.mock
async def test_hp_laserjet_detection():
    respx.get("http://printer.local/").mock(
        return_value=httpx.Response(
            200,
            headers={"Server": "HP LaserJet 400 M401dne"},
            content="<html><head><title>HP LaserJet 400 M401dne</title></head><body>HP Printer</body></html>"
        )
    )
    respx.get(url__regex=r"http://printer.local/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://printer.local/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://printer.local/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModulePrinter(crawler, persister, options, crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "HP LaserJet 400 M401dne", "versions": [""], "categories": ["Network Equipment"], "groups": ["Printers"]}'
        )
        assert persister.add_payload.call_args_list[0][1]["module"] == "printer"

@pytest.mark.asyncio
@respx.mock
async def test_hp_laserjet_detection_with_firmware_version():
    respx.get("http://printer.local/").mock(
        return_value=httpx.Response(
            200,
            headers={"Server": "HP LaserJet 400 M401dne"},
            content="<html><head><title>HP LaserJet 400 M401dne</title></head><body>HP Printer</body></html>"
        )
    )

    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
    <prdcfgdyn2:ProductConfigDyn xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:dd="http://www.hp.com/schemas/imaging/con/dictionaries/1.0/" xmlns:prdcfgdyn2="http://www.hp.com/schemas/imaging/con/ledm/productconfigdyn/2009/03/16" xmlns:prdcfgdyn="http://www.hp.com/schemas/imaging/con/ledm/productconfigdyn/2007/11/05" xsi:schemaLocation="http://www.hp.com/schemas/imaging/con/ledm/productconfigdyn/2009/03/16 ../schemas/ledm2/ProductConfigDyn.xsd                               http://www.hp.com/schemas/imaging/con/ledm/productconfigdyn/2007/11/05 ../schemas/ProductConfigDyn.xsd                               http://www.hp.com/schemas/imaging/con/dictionaries/1.0/ ../schemas/dd/DataDictionaryMasterLEDM.xsd">
	<dd:Version>
		<dd:Revision>SVN-IPG-LEDM.690</dd:Revision>
		<dd:Date>2011-03-30</dd:Date>
	</dd:Version>
	<prdcfgdyn:ProductInformation>
		<dd:Version>
			<dd:Revision>V2.12.0</dd:Revision>
			<dd:Date>2022-04-28</dd:Date>
		</dd:Version>
	</prdcfgdyn:ProductInformation>
	</prdcfgdyn2:ProductConfigDyn>"""

    respx.get("http://printer.local/DevMgmt/ProductConfigDyn.xml").mock(
        return_value=httpx.Response(
            200,
            content=xml_content
        )
    )
    respx.get(url__regex=r"http://printer.local/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://printer.local/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://printer.local/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModulePrinter(crawler, persister, options, crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "HP LaserJet 400 M401dne", "versions": ["V2.12.0"], "categories": ["Network Equipment"], "groups": ["Printers"]}'
        )
        assert persister.add_payload.call_args_list[0][1]["module"] == "printer"

@pytest.mark.asyncio
@respx.mock
async def test_epson_l6290_detection():
    respx.get("http://printer.local/").mock(
        return_value=httpx.Response(
            200,
            headers={"Server": "EPSON L6290 Series"},
            content="<html><head><title></title></head><body>Home page Printer</body></html>"
        )
    )
    respx.get(url__regex=r"http://printer.local/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://printer.local/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://printer.local/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModulePrinter(crawler, persister, options, crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "EPSON L6290 Series", "versions": [""], "categories": ["Network Equipment"], "groups": ["Printers"]}'
        )
        assert persister.add_payload.call_args_list[0][1]["module"] == "printer"

@pytest.mark.asyncio
@respx.mock
async def test_epson_l6290_detection_with_fw_version():
    respx.get("http://printer.local/").mock(
        return_value=httpx.Response(
            200,
            headers={"Server": "EPSON L6290 Series"},
            content="<html><head><title></title></head><body>Home page Printer</body></html>"
        )
    )

    respx.get("http://printer.local/PRESENTATION/HTML/TOP/INDEX.html").mock(
        return_value=httpx.Response(
            200,
            headers={"Server": "EPSON L6290 Series"},
            content='<html><head><title></title></head><body><div class="section main-menu-section-nolink clearfix">'
                    '<h2 class="menu">Firmware Update</h2><p class="guide">Current Version:05.13.XA22P1</p>'
                    '</div></body></html>"'
        )
    )
    respx.get(url__regex=r"http://printer.local/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://printer.local/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://printer.local/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModulePrinter(crawler, persister, options, crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "EPSON L6290 Series", "versions": ["05.13.XA22P1"], "categories": ["Network Equipment"], "groups": ["Printers"]}'
        )
        assert persister.add_payload.call_args_list[0][1]["module"] == "printer"

@pytest.mark.asyncio
async def test_get_firmware_version_unknown_brand():
    module = ModulePrinter(AsyncMock(), AsyncMock(), {}, AsyncMock())

    result = await module.get_firmware_version("http://printer.local", "canon")

    assert result == ""


@pytest.mark.asyncio
@respx.mock
async def test_canon_printer_through_html():
    respx.get("http://printer.local/").mock(
        return_value=httpx.Response(
            200,
            headers={"Server": "Canon Web Server"},
            content='<html><head><title></title><p id="deviceType"><span id="deviceName">MF750C Series</span></p></html>'
        )
    )

    respx.get(url__regex=r"http://printer.local/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://printer.local/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://printer.local/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModulePrinter(crawler, persister, options, crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "Canon MF750C Series", "versions": [""], "categories": ["Network Equipment"], "groups": ["Printers"]}'
        )
        assert persister.add_payload.call_args_list[0][1]["module"] == "printer"

@pytest.mark.asyncio
@respx.mock
async def test_canon_printer_via_headers():
    respx.get("http://printer.local/").mock(
        return_value=httpx.Response(
            200,
            headers={"Server": "Canon MF633C Caster"},
            content='<html><head><title></title><body>Canon Printer</body></html>'
        )
    )

    respx.get(url__regex=r"http://printer.local/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://printer.local/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://printer.local/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModulePrinter(crawler, persister, options, crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "Canon MF633C Caster", "versions": [""], "categories": ["Network Equipment"], "groups": ["Printers"]}'
        )
        assert persister.add_payload.call_args_list[0][1]["module"] == "printer"


@pytest.mark.asyncio
async def test_get_firmware_version_unknown_brand():
    module = ModulePrinter(AsyncMock(), AsyncMock(), {}, AsyncMock())

    result = await module.get_firmware_version("http://printer.local", "canon")

    assert result == ""

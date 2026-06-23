
import datetime
import logging
import os
import random
import shutil
import tempfile
from io import BytesIO
from zipfile import ZipFile

from flask_server.utils.common import get_random_string, validate_email_account, validate_username, validate_password, validate_domain

# from ziplib import MODE_DIRECTORY

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.dirname(os.path.dirname(BASE_DIR)))
UPLOAD_DIR = os.path.join(PROJECT_DIR,"Honeyfiles","upload")
GENERATE_DIR = os.path.join(PROJECT_DIR,"Honeyfiles","generate")
TEMPLATE_DIR = os.path.join(PROJECT_DIR,"template")
EXCEL_TEMPLATE = os.path.join(TEMPLATE_DIR,"template.xlsx")

def zipinfo_contents_replace(zipfile=None, zipinfo=None, search=None, replace=None):
    """Given an entry in a zip file, extract the file and perform a search
    and replace on the contents. Returns the contents as a string."""
    dirname = tempfile.mkdtemp(dir=os.path.join(PROJECT_DIR, "temp"))
    fname = zipfile.extract(zipinfo, dirname)
    with open(fname, "r", encoding="utf-8") as fd:
        contents = fd.read().replace(search, replace)
    shutil.rmtree(dirname)
    return contents


def make_canary_msexcel(url=None, template=EXCEL_TEMPLATE):
    output_buf = BytesIO()
    output_zip = ZipFile(output_buf, "w")
    now = datetime.datetime.now()
    now_ts = format_time_for_doc(now)
    created_ts = format_time_for_doc(
        now
        - datetime.timedelta(
            days=random.randint(1, 25),
            hours=random.randint(1, 24),
            seconds=random.randint(1, 60),
        )
    )
    with ZipFile(EXCEL_TEMPLATE, "r") as doc:
        for entry in doc.filelist:
            if entry.external_attr & 0x10:
                continue

            contents = _zipinfo_contents_replace_memory(
                zip_file=doc, zip_info=entry, search="HONEYDROP_TOKEN_URL", replace=url
            )
            contents = contents.replace("aaaaaaaaaaaaaaaaaaaa", created_ts)
            contents = contents.replace("bbbbbbbbbbbbbbbbbbbb", now_ts)
            output_zip.writestr(entry, contents)
    output_zip.close()
    return output_buf.getvalue()


def format_time_for_doc(time):
    return time.strftime("%Y-%m-%d") + "T" + time.strftime("%H:%M:%S") + "Z"


def self_gen_token_excel(input_token=None, filename=None, dir="./Honeyfiles/generate/"):
    filename = filename + ".xlsx"
    dir = os.path.join(dir, filename)
    try:
        with open(dir, "wb+") as f:
            f.write(make_canary_msexcel(url=input_token))
    except Exception as e:
        print(e)
        return e
    return filename


def zipinfo_contents_replace2(zipfile=None, zipinfo=None, search=None, replace=None):
    """Given an entry in a zip file, extract the file and perform a search
    and replace on the contents. Returns the contents as a string."""
    dirname = tempfile.mkdtemp(dir=os.path.join(PROJECT_DIR, "temp"))
    fname = zipfile.extract(zipinfo, dirname)
    if ("xml" in fname) or ("rels" in fname):
        with open(fname, "r", encoding="utf-8") as fd:
            contents = fd.read().replace(search, replace)
            if zipinfo.filename == "xl/worksheets/sheet1.xml":
                if "xmlns:r" not in contents:
                    contents = contents.replace(
                        "<worksheet",
                        '<worksheet xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"',
                    )
    else:
        with open(fname, "rb") as fd:
            contents = fd.read()

    shutil.rmtree(dirname)
    return contents


def _zipinfo_contents_replace_memory(zip_file=None, zip_info=None, search=None, replace=None):
    with zip_file.open(zip_info, "r") as fd:
        contents = fd.read().decode("utf-8").replace(search, replace)
        if zip_info.filename == "xl/worksheets/sheet1.xml" and "xmlns:r" not in contents:
            contents = contents.replace(
                "<worksheet",
                '<worksheet xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"',
            )
        return contents


def _zipinfo_contents_replace2_memory(zip_file=None, zip_info=None, search=None, replace=None):
    if ("xml" in zip_info.filename) or ("rels" in zip_info.filename):
        with zip_file.open(zip_info, "r") as fd:
            contents = fd.read().decode("utf-8").replace(search, replace)
            if zip_info.filename == "xl/worksheets/sheet1.xml" and "xmlns:r" not in contents:
                contents = contents.replace(
                    "<worksheet",
                    '<worksheet xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"',
                )
            return contents
    with zip_file.open(zip_info, "r") as fd:
        return fd.read()


def make_canary_msexcel2(input_file, url=None):
    output_buf = BytesIO()
    output_zip = ZipFile(output_buf, "w")
    with ZipFile(input_file, "r") as doc:
        flag = 0
        for entry in doc.filelist:
            search = "xxxxxxxxxxxxx"
            replace = "xxxxxxxxxxxxxxx"
            if entry.filename == "xl/drawings/drawing1.xml":
                flag = 1

            elif entry.filename == "xl/drawings/_rels/drawing1.xml.rels":
                flag = 1

            if entry.external_attr & 0x10:
                continue
        if flag == 0:
            output_zip.writestr(
                "xl/drawings/drawing1.xml",
                r'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><xdr:twoCellAnchor editAs="oneCell"><xdr:from><xdr:col>61</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>376</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from><xdr:to><xdr:col>70</xdr:col><xdr:colOff>190500</xdr:colOff><xdr:row>397</xdr:row><xdr:rowOff>177800</xdr:rowOff></xdr:to><xdr:pic><xdr:nvPicPr><xdr:cNvPr id="3" name="Picture 2"><a:extLst><a:ext uri="{FF2B5EF4-FFF2-40B4-BE49-F238E27FC236}"><a16:creationId xmlns:a16="http://schemas.microsoft.com/office/drawing/2014/main" id="{E90E5A81-5E9B-744C-9F18-59568A01D25B}"/></a:ext></a:extLst></xdr:cNvPr><xdr:cNvPicPr><a:picLocks noChangeAspect="1"/></xdr:cNvPicPr></xdr:nvPicPr><xdr:blipFill><a:blip xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:link="rId0"/><a:stretch><a:fillRect/></a:stretch></xdr:blipFill><xdr:spPr><a:xfrm><a:off x="50355500" y="76403200"/><a:ext cx="7620000" cy="4445000"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></xdr:spPr></xdr:pic><xdr:clientData/></xdr:twoCellAnchor></xdr:wsDr>',
            )
            output_zip.writestr(
                "xl/drawings/_rels/drawing1.xml.rels",
                r'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId0" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="'
                + url
                + '" TargetMode="External"/></Relationships>',
            )
            output_zip.writestr(
                "xl/worksheets/_rels/sheet1.xml.rels",
                r'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing" Target="../drawings/drawing1.xml"/></Relationships>',
            )
            for entry in doc.filelist:
                search = "xxxxxxxxxxxxx"
                replace = "xxxxxxxxxxxxxxx"

                # 在[Content_Types].xml添加语句
                if entry.filename == "[Content_Types].xml":
                    search = "</Types>"
                    replace = '<Override PartName="/xl/drawings/drawing1.xml" ContentType="application/vnd.openxmlformats-officedocument.drawing+xml"/></Types>'
                # 在sheet1.xml添加语句
                if entry.filename == "xl/worksheets/sheet1.xml":
                    search = "</worksheet>"
                    replace = '<headerFooter /><drawing r:id="rId1" /></worksheet>'
                if entry.filename == "xl/worksheets/_rels/sheet1.xml.rels":
                    continue
                if entry.external_attr & 0x10:
                    continue
                contents = _zipinfo_contents_replace2_memory(
                    zip_file=doc, zip_info=entry, search=search, replace=replace
                )
                output_zip.writestr(entry, contents)
        else:
            for entry in doc.filelist:
                search = "xxxxxxxxxxxxx"
                replace = "xxxxxxxxxxxxxxx"
                if entry.filename == "xl/drawings/drawing1.xml":
                    flag = 1
                    search = "</xdr:wsDr>"
                    replace = '<xdr:twoCellAnchor editAs="oneCell"><xdr:from><xdr:col>61</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>376</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from><xdr:to><xdr:col>70</xdr:col><xdr:colOff>190500</xdr:colOff><xdr:row>397</xdr:row><xdr:rowOff>177800</xdr:rowOff></xdr:to><xdr:pic><xdr:nvPicPr><xdr:cNvPr id="3" name="Picture 2"><a:extLst><a:ext uri="{FF2B5EF4-FFF2-40B4-BE49-F238E27FC236}"><a16:creationId xmlns:a16="http://schemas.microsoft.com/office/drawing/2014/main" id="{E90E5A81-5E9B-744C-9F18-59568A01D25B}"/></a:ext></a:extLst></xdr:cNvPr><xdr:cNvPicPr><a:picLocks noChangeAspect="1"/></xdr:cNvPicPr></xdr:nvPicPr><xdr:blipFill><a:blip xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:link="rId0"/><a:stretch><a:fillRect/></a:stretch></xdr:blipFill><xdr:spPr><a:xfrm><a:off x="50355500" y="76403200"/><a:ext cx="7620000" cy="4445000"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></xdr:spPr></xdr:pic><xdr:clientData/></xdr:twoCellAnchor></xdr:wsDr>'
                # 在drawing0.xml.rels添加语句
                elif entry.filename == "xl/drawings/_rels/drawing1.xml.rels":
                    flag = 1
                    search = "</Relationships>"
                    replace = (
                        '<Relationship Id="rId0" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="'
                        + url
                        + '" TargetMode="External"/></Relationships>'
                    )
                if entry.external_attr & 0x10:
                    continue
                contents = _zipinfo_contents_replace2_memory(
                    zip_file=doc, zip_info=entry, search=search, replace=replace
                )
                output_zip.writestr(entry, contents)
    output_zip.close()
    return output_buf.getvalue()


def gen_tokened_excel(input_file, token, source):
    # input_file：当使用模板生成蜜点文件时，input_file为模板文件名，当使用用户上传文件生成蜜点文件时，input_file为用户上传文件名
    # dir: 模板文件/上传文件的路径
    # source: 0 模板文件 1 用户上传文件
    filename = os.path.splitext(os.path.basename(str(input_file)))[0]
    if source == 0:
        # 本地检测模板文件是否存在
        if input_file is None or input_file == "":
            filename = ""
            input_file = "template.xlsx"  # 默认模板文件名
        else:
            input_file = "template-" + input_file  # 还原模板文件原名template-xxx.xlsx
        input_file = os.path.join(TEMPLATE_DIR, input_file) # 模板文件路径
        if not os.path.exists(input_file):
            return 1, "Template not found"
    elif source == 1:
        # 本地检测用户上传文件是否存在
        input_file = os.path.join(UPLOAD_DIR, input_file)
        if not os.path.exists(input_file):
            return 1, "The uploaded file was not found"
    else:
        return 1, "Source error"
    if (filename == "") or (filename is None):
        filename_new = get_random_string(5) + ".xlsx"
    else:
        filename_new = (
            filename + "-" + get_random_string(5) + ".xlsx"
        )  # 文件名后附带随机字符串，防止蜜点文件重名
    output_file = os.path.join(GENERATE_DIR, filename_new)
    print("输入文件:", input_file, "输出文件:", output_file)
    

    try:
        with open(output_file, "wb+") as f:
            f.write(make_canary_msexcel2(input_file, url=token))
    except Exception as e:
        print("[ERROR]:" + str(e))
        return 1, str(e)
    return 0, filename_new

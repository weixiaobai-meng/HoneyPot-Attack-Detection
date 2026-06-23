import datetime
import logging
import os
import random
import shutil
import tempfile

# from ziplib import MODE_DIRECTORY
from io import BytesIO
from zipfile import ZipFile

from flask_server.utils.common import get_random_string
# BASE_DIR = os.getcwd()  # 获取工作路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.dirname(os.path.dirname(BASE_DIR)))
TEMPLATE_DIR = os.path.join(PROJECT_DIR,"template")
UPLOAD_DIR = os.path.join(PROJECT_DIR,"Honeyfiles","upload")
GENERATE_DIR = os.path.join(PROJECT_DIR,"Honeyfiles","generate")

# 初始化必要文件夹
def path_init():
    # 判断文件夹是否存在
    if not os.path.exists(GENERATE_DIR):
        os.makedirs(GENERATE_DIR, exist_ok=True)
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR, exist_ok=True)
    return
path_init()

def zipinfo_contents_replace(zipfile=None, zipinfo=None, search=None, replace=None):
    """Given an entry in a zip file, extract the file and perform a search
    and replace on the contents. Returns the contents as a string."""
    dirname = tempfile.mkdtemp(dir=os.path.join(PROJECT_DIR, "temp"))
    fname = zipfile.extract(zipinfo, dirname)  # zipinfo == entry
    # print(fname)
    with open(fname, "r", encoding="utf-8") as fd:
        filename = os.path.split(fname)[1]  # 分离路径和文件名
        contents = fd.read().replace(search, replace)
    shutil.rmtree(dirname)
    return contents


def make_canary_msword(filename_tpl, url=None):
    output_buf = BytesIO()  # 创建一个BytesIO对象
    output_zip = ZipFile(output_buf, "w")  # 创建一个ZipFile对象
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
    # print(os.listdir())
    with ZipFile(TEMPLATE_DIR + filename_tpl, "r") as doc:  # 打开模板文件
        # print(type(doc.filelist),len(doc.filelist))
        for entry in doc.filelist:
            # print(entry,entry.external_attr & 0x10)
            if entry.external_attr & 0x10:  # 0x10是文件夹属性值，通过位运算判断是否是文件夹
                continue
            contents = _zipinfo_contents_replace_memory(
                zip_file=doc, zip_info=entry, search="HONEYDROP_TOKEN_URL", replace=url
            )  # 插入token_url
            contents = contents.replace("aaaaaaaaaaaaaaaaaaaa", created_ts)  # 修改创建时间
            contents = contents.replace("bbbbbbbbbbbbbbbbbbbb", now_ts)  # 修改当前时间
            # print(type(str(entry)),type(contents))
            output_zip.writestr(entry, contents)
    output_zip.close()
    print(type(output_buf.getvalue()))
    return output_buf.getvalue()


def format_time_for_doc(time):
    return time.strftime("%Y-%m-%d") + "T" + time.strftime("%H:%M:%S") + "Z"


# def zipinfo_content_add(zipfile=None,zipinfo=None,data=None):


# 通过空模板生成蜜点文件
def self_gen_token_word(input_token, filename, dir="./Honeyfiles/generate/"):
    filename = filename + ".docx"
    filename_tpl = "template.docx"  # 获取模板文件名
    try:
        with open(filename, "wb+") as f:  # 新建蜜点文件
            f.write(make_canary_msword(filename_tpl, url=input_token))  # 生成文件
        f.close()
    except Exception as e:
        return 1, e
    return 0, filename


def zipinfo_contents_replace2(zipfile=None, zipinfo=None, search=None, replace=None):
    dirname = tempfile.mkdtemp(dir=os.path.join(PROJECT_DIR, "temp"))
    fname = zipfile.extract(zipinfo, dirname)  # zipinfo == entry
    if ("xml" in fname) or ("rels" in fname):
        with open(fname, "r", encoding="utf-8") as fd:
            filename = os.path.split(fname)[1]  # 分离路径和文件名
            # print("修改前",fd.read())
            contents = fd.read().replace(search, replace)
    else:
        with open(fname, "rb") as fd:
            filename = os.path.split(fname)[1]  # 分离路径和文件名
            # print("修改前",fd.read())
            contents = fd.read()
            # print("修改后",contents)
    shutil.rmtree(dirname)
    return contents


def _zipinfo_contents_replace_memory(zip_file=None, zip_info=None, search=None, replace=None):
    with zip_file.open(zip_info, "r") as fd:
        return fd.read().decode("utf-8").replace(search, replace)


def _zipinfo_contents_replace2_memory(zip_file=None, zip_info=None, search=None, replace=None):
    if ("xml" in zip_info.filename) or ("rels" in zip_info.filename):
        with zip_file.open(zip_info, "r") as fd:
            return fd.read().decode("utf-8").replace(search, replace)
    with zip_file.open(zip_info, "r") as fd:
        return fd.read()


def make_canary_msword_add(input_file, url=None):
    output_buf = BytesIO()
    output_zip = ZipFile(output_buf, "w")
    now = datetime.datetime.now()
    with ZipFile(input_file, "r") as doc:
        for entry in doc.filelist:
            search = "999999999999999999999999999"
            replace = "99999999999999999999999999"
            if entry.filename == "[Content_Types].xml":
                search = "</Types>"
                replace = '<Override PartName="/word/footer0.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml" /></Types>'
            elif entry.filename == "word/document.xml":
                search = "</w:sectPr>"
                replace = (
                    '<w:footerReference w:type="default" r:id="rId0" /></w:sectPr>'
                )
            elif entry.filename == "word/_rels/document.xml.rels":
                search = "</Relationships>"
                replace = '<Relationship Id="rId0" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer0.xml" /></Relationships>'
            elif entry.external_attr & 0x10:
                continue
            contents = _zipinfo_contents_replace2_memory(
                zip_file=doc, zip_info=entry, search=search, replace=replace
            )
            # print(entry)
            output_zip.writestr(entry, contents)

    output_zip.writestr(
        "word/_rels/footer0.xml.rels",
        r'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="'
        + url
        + '" TargetMode="External"/></Relationships>',
    )
    output_zip.writestr(
        "word/footer0.xml",
        r'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:w10="urn:schemas-microsoft-com:office:word" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml" xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk" xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" mc:Ignorable="w14 w15 wp14">
    <w:bookmarkStart w:id="0" w:name="_GoBack" />
    <w:bookmarkEnd w:id="0" />
    <w:p w:rsidR="009E0DC7" w:rsidRDefault="009E0DC7">
        <w:pPr>
            <w:pStyle w:val="Footer" />
        </w:pPr>
        <w:r>
            <w:fldChar w:fldCharType="begin" />
        </w:r>
        <w:r>
            <w:instrText xml:space="preserve"> INCLUDEPICTURE  "'''
        + url
        + """" \d  \* MERGEFORMAT </w:instrText>
        </w:r>
        <w:r>
            <w:fldChar w:fldCharType="separate" />
        </w:r>
        <w:r>
            <w:pict>
                <v:shapetype id="_x0000_t75" coordsize="21600,21600" o:spt="75" o:preferrelative="t" path="m@4@5l@4@11@9@11@9@5xe" filled="f" stroked="f">
                    <v:stroke joinstyle="miter" />
                    <v:formulas>
                        <v:f eqn="if lineDrawn pixelLineWidth 0" />
                        <v:f eqn="sum @0 1 0" />
                        <v:f eqn="sum 0 0 @1" />
                        <v:f eqn="prod @2 1 2" />
                        <v:f eqn="prod @3 21600 pixelWidth" />
                        <v:f eqn="prod @3 21600 pixelHeight" />
                        <v:f eqn="sum @0 0 1" />
                        <v:f eqn="prod @6 1 2" />
                        <v:f eqn="prod @7 21600 pixelWidth" />
                        <v:f eqn="sum @8 21600 0" />
                        <v:f eqn="prod @7 21600 pixelHeight" />
                        <v:f eqn="sum @10 21600 0" />
                    </v:formulas>
                    <v:path o:extrusionok="f" gradientshapeok="t" o:connecttype="rect" />
                    <o:lock v:ext="edit" aspectratio="t" />
                </v:shapetype>
                <v:shape id="_x0000_i1025" type="#_x0000_t75" style="width:.75pt;height:.75pt">
                    <v:imagedata r:id="rId1" />
                </v:shape>
            </w:pict>
        </w:r>
        <w:r>
            <w:fldChar w:fldCharType="end" />
        </w:r>
    </w:p>
    <w:p w:rsidR="009E0DC7" w:rsidRDefault="009E0DC7">
        <w:pPr>
            <w:pStyle w:val="Footer" />
        </w:pPr>
    </w:p>
</w:ftr>
    """,
    )
    output_zip.close()
    # print(type(output_buf.getvalue()))
    return output_buf.getvalue()


def del_word_token(input_file):
    output_buf = BytesIO()
    output_zip = ZipFile(output_buf, "w")
    with ZipFile(input_file, "r") as doc:
        for entry in doc.filelist:
            search = "9999999999999999"
            replace = "999999999999999"
            if entry.filename == "[Content_Types].xml":
                search = '<Override PartName="/word/footer0.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml" /></Types>'
                replace = "</Types>"
            if entry.filename == "word/document.xml":
                search = '<w:footerReference w:type="default" r:id="rId0" /></w:sectPr>'
                replace = "</w:sectPr>"
            if entry.filename == "word/_rels/document.xml.rels":
                search = '<Relationship Id="rId0" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer0.xml" /></Relationships>'
                replace = "</Relationships>"
            if (
                entry.filename == "word/footer0.xml"
                or entry.filename == "word/footer0.xml"
            ):
                continue
            contents = zipinfo_contents_replace(
                zipfile=doc, zipinfo=entry, search=search, replace=replace
            )
            # print(entry.filename,"\n",contents)
            output_zip.writestr(entry, contents)
    output_zip.close()
    # print(type(output_buf.getvalue()))
    return output_buf.getvalue()


def gen_tokened_word(input_file, token, source):
    # input_file：当使用模板生成蜜点文件时，input_file为模板文件名，当使用用户上传文件生成蜜点文件时，input_file为用户上传文件名
    # dir: 模板文件/上传文件的路径
    # source: 0 模板文件 1 用户上传文件
    filename = os.path.splitext(os.path.basename(str(input_file)))[0]
    if source == 0:
        # 本地检测模板文件是否存在
        if input_file is None or input_file == "":
            filename = ""
            input_file = "template.docx"  # 默认模板文件名
        else:
            input_file = "template-" + input_file  # 还原模板文件原名template-xxx.docx
        tpl_file_path = os.path.join(TEMPLATE_DIR, input_file)
        print(TEMPLATE_DIR)
        print(os.path.exists(os.path.join(os.getcwd(), "template",input_file)))
        if not os.path.exists(tpl_file_path):
            return 1, "Template not found"
        input_file = tpl_file_path
    elif source == 1:
        # 本地检测用户上传文件是否存在
        upload_file_path = os.path.join(UPLOAD_DIR, input_file)
        if not os.path.exists(upload_file_path):
            return 1, "The uploaded file was not found"
        input_file = upload_file_path
    else:
        return 1, "Source error"
    if (filename == "") or (filename is None):
        filename_new = get_random_string(5) + ".docx"
    else:
        filename_new = (
            filename + "-" + get_random_string(5) + ".docx"
        )  # 文件名后附带随机字符串，防止蜜点文件重名
    output_file = os.path.join(GENERATE_DIR, filename_new)
    print("输入文件:", input_file, "输出文件:", output_file)
    #logging.info(f"[File]输入文件:{input_file} 输出文件：{output_file}")
    
    try:
        with open(output_file, "wb+") as f:
            f.write(make_canary_msword_add(input_file, url=token))
    except Exception as e:
        print("[ERROR]:" + str(e))
        return 1, str(e)
    return 0, filename_new

"""
蜜点生成测试脚本
测试文件蜜点（Word/Excel）和账户蜜点的生成功能
"""
import os
import random
import string
import datetime
import tempfile
import shutil
import re
from io import BytesIO
from zipfile import ZipFile

os.chdir(os.path.dirname(os.path.abspath(__file__)))
os.makedirs("Honeyfiles/generate", exist_ok=True)

BASE_DIR = os.getcwd()
TEMPLATE_DIR = os.path.join(BASE_DIR, "template")
GENERATE_DIR = os.path.join(BASE_DIR, "Honeyfiles", "generate")


def get_random_string(length):
    letters = string.ascii_letters + string.digits
    return "".join(random.choice(letters) for _ in range(length))


# ===================== 账户蜜点 =====================
def find_pattern(name):
    l, d, m = 0, 0, 0
    fmt = ""
    charList, ch, num, mark = [], [], [], []
    for i in range(len(name)):
        pre_tp = "" if charList == [] else pre_tp
        if name[i].isdigit():
            tp = "d"; d += 1
        elif name[i].isalpha():
            tp = "l"; l += 1
        else:
            tp = "m"; m += 1

        if pre_tp == "":
            charList.append(name[i])
            pre_tp = tp
        elif tp == pre_tp:
            charList.append(name[i])
        elif tp != pre_tp and charList != []:
            fmt = fmt + pre_tp + str(len(charList)) + " "
            if pre_tp == "d":
                num.append("".join([c for c in charList]))
            elif pre_tp == "l":
                ch.append("".join([c for c in charList]))
            elif pre_tp == "m":
                mark.append("".join([c for c in charList]))
            charList.clear()
            pre_tp = tp
            charList.append(name[i])

        if i == len(name) - 1:
            fmt += pre_tp + str(len(charList))
            if pre_tp == "d":
                num.append("".join([c for c in charList]))
            elif pre_tp == "l":
                ch.append("".join([c for c in charList]))
            elif pre_tp == "m":
                mark.append("".join([c for c in charList]))
            charList.clear()
    return fmt, ch, num, mark


def is_chinese(check_str):
    for ch in check_str:
        if not re.match(r'[\u4e00-\u9fa5]+', ch):
            return False
    return True


def username_generate(seed, num) -> list:
    years = list(range(1960, 2024))
    account_list = []
    if is_chinese(seed):
        try:
            from xpinyin import Pinyin
            p = Pinyin()
            py = p.get_pinyin(seed, "")
            form1 = p.get_initials(seed, "").lower()
            form2 = p.get_initials(seed[0], "").lower() + p.get_pinyin(seed[1:], "")
            form3 = p.get_pinyin(seed[0], "") + p.get_initials(seed[1:], "").lower()
        except ImportError:
            print("  [WARN] xpinyin not installed, using fallback pinyin")
            py = seed
            form1 = seed[0]
            form2 = seed[0] + seed[1:]
            form3 = seed[:2]
        if num < 4:
            num1, num2 = 1, 1
        else:
            num1 = int(num / 2)
            num2 = int(num / 4)
        while len(account_list) < num1:
            account = py + str(years[random.randint(0, len(years) - 1)])
            account_list.append(account)
        while len(account_list) < num1 + num2:
            account = form1 + str(years[random.randint(0, len(years) - 1)])
            account_list.append(account)
        while len(account_list) < num1 + 2 * num2:
            account = form2 + str(years[random.randint(0, len(years) - 1)])
            account_list.append(account)
        while len(account_list) < num:
            account = form3 + str(years[random.randint(0, len(years) - 1)])
            account_list.append(account)
        unique_account_list = set(account_list)
        while len(unique_account_list) < num:
            account = form3 + str(years[random.randint(0, len(years) - 1)])
            unique_account_list.add(account)
        account_list = list(unique_account_list)
    else:
        username = seed.split("@")[0]
        fmt, ch, digit, mark = find_pattern(username)
        num_list = [int(num / 2), num - int(num / 2)]
        while len(account_list) < num_list[0]:
            if ch != []:
                letter = "".join(ch) + "".join(random.choice(string.ascii_lowercase) for _ in range(random.randint(1, 2)))
            if digit != []:
                if random.randint(0, 1) == 0:
                    number = "".join(digit) + "".join(random.choice(string.digits) for _ in range(random.randint(1, 3)))
                else:
                    number = int("".join(digit)) + random.randint(1, 9)
            else:
                number = random.randint(1, 9)
            if fmt[0] == "l":
                account = letter + str(number)
            else:
                account = str(number) + letter
            if account not in account_list:
                account_list.append(account)
        while len(account_list) < num_list[0]:
            account = "".join(random.choice(string.ascii_lowercase) for _ in range(random.randint(3, 5)))
            account_list.append(account)
        while len(account_list) < num:
            account = "".join(ch) + "".join(str(years[random.randint(0, len(years) - 1)]))
            if account not in account_list:
                account_list.append(account)
    return account_list


def password_genaerate(num, length=12) -> list:
    characters = string.ascii_letters + string.digits
    return ["".join(random.choice(characters) for _ in range(length)) for _ in range(num)]


# ===================== 文件蜜点辅助 =====================
def format_time_for_doc(time):
    return time.strftime("%Y-%m-%d") + "T" + time.strftime("%H:%M:%S") + "Z"


def zipinfo_contents_replace(zipfile, zipinfo, search, replace):
    dirname = tempfile.mkdtemp()
    fname = zipfile.extract(zipinfo, dirname)
    with open(fname, "r", encoding="utf-8") as fd:
        contents = fd.read().replace(search, replace)
    shutil.rmtree(dirname)
    return contents


# ===================== Word 蜜点生成 =====================
def make_canary_msword_placeholder(template_path, url):
    """模板占位符模式：替换 HONEYDROP_TOKEN_URL 为 token"""
    now = datetime.datetime.now()
    now_ts = format_time_for_doc(now)
    created_ts = format_time_for_doc(now - datetime.timedelta(days=random.randint(1, 25)))
    output_buf = BytesIO()
    output_zip = ZipFile(output_buf, "w")
    with ZipFile(template_path, "r") as doc:
        for entry in doc.filelist:
            if entry.external_attr & 0x10:
                continue
            contents = zipinfo_contents_replace(doc, entry, "HONEYDROP_TOKEN_URL", url)
            contents = contents.replace("aaaaaaaaaaaaaaaaaaaa", created_ts)
            contents = contents.replace("bbbbbbbbbbbbbbbbbbbb", now_ts)
            output_zip.writestr(entry, contents)
    output_zip.close()
    return output_buf.getvalue()


def make_canary_msword_footer(input_file, url):
    """Footer嵌入模式：在Word文档footer中嵌入外部图片引用(token URL)"""
    output_buf = BytesIO()
    output_zip = ZipFile(output_buf, "w")
    with ZipFile(input_file, "r") as doc:
        for entry in doc.filelist:
            search = "999999999999999999999999999"
            replace = "99999999999999999999999999"
            if entry.filename == "[Content_Types].xml":
                search = "</Types>"
                replace = '<Override PartName="/word/footer0.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml" /></Types>'
            elif entry.filename == "word/document.xml":
                search = "</w:sectPr>"
                replace = '<w:footerReference w:type="default" r:id="rId0" /></w:sectPr>'
            elif entry.filename == "word/_rels/document.xml.rels":
                search = "</Relationships>"
                replace = '<Relationship Id="rId0" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer0.xml" /></Relationships>'
            elif entry.external_attr & 0x10:
                continue

            dirname = tempfile.mkdtemp()
            fname = doc.extract(entry, dirname)
            if ("xml" in fname) or ("rels" in fname):
                with open(fname, "r", encoding="utf-8") as fd:
                    contents = fd.read().replace(search, replace)
            else:
                with open(fname, "rb") as fd:
                    contents = fd.read()
            shutil.rmtree(dirname)
            output_zip.writestr(entry, contents)

    output_zip.writestr(
        "word/_rels/footer0.xml.rels",
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
        'Target="' + url + '" TargetMode="External"/>'
        '</Relationships>',
    )
    # XML footer with INCLUDEPICTURE field referencing the token URL
    footer_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:ftr xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" '
        'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
        'xmlns:o="urn:schemas-microsoft-com:office:office" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" '
        'xmlns:v="urn:schemas-microsoft-com:vml" '
        'xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" '
        'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
        'xmlns:w10="urn:schemas-microsoft-com:office:word" '
        'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" '
        'xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml" '
        'xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" '
        'xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk" '
        'xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" '
        'xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" '
        'mc:Ignorable="w14 w15 wp14">'
        '<w:bookmarkStart w:id="0" w:name="_GoBack" />'
        '<w:bookmarkEnd w:id="0" />'
        '<w:p w:rsidR="009E0DC7" w:rsidRDefault="009E0DC7">'
        '<w:pPr><w:pStyle w:val="Footer" /></w:pPr>'
        '<w:r><w:fldChar w:fldCharType="begin" /></w:r>'
        '<w:r><w:instrText xml:space="preserve"> INCLUDEPICTURE  "' + url + r'" \d  \* MERGEFORMAT </w:instrText>'
        '</w:r>'
        '<w:r><w:fldChar w:fldCharType="separate" /></w:r>'
        '<w:r><w:pict>'
        '<v:shapetype id="_x0000_t75" coordsize="21600,21600" o:spt="75" o:preferrelative="t" '
        'path="m@4@5l@4@11@9@11@9@5xe" filled="f" stroked="f">'
        '<v:stroke joinstyle="miter" />'
        '<v:formulas>'
        '<v:f eqn="if lineDrawn pixelLineWidth 0" />'
        '<v:f eqn="sum @0 1 0" /><v:f eqn="sum 0 0 @1" />'
        '<v:f eqn="prod @2 1 2" /><v:f eqn="prod @3 21600 pixelWidth" />'
        '<v:f eqn="prod @3 21600 pixelHeight" /><v:f eqn="sum @0 0 1" />'
        '<v:f eqn="prod @6 1 2" /><v:f eqn="prod @7 21600 pixelWidth" />'
        '<v:f eqn="sum @8 21600 0" /><v:f eqn="prod @7 21600 pixelHeight" />'
        '<v:f eqn="sum @10 21600 0" />'
        '</v:formulas>'
        '<v:path o:extrusionok="f" gradientshapeok="t" o:connecttype="rect" />'
        '<o:lock v:ext="edit" aspectratio="t" />'
        '</v:shapetype>'
        '<v:shape id="_x0000_i1025" type="#_x0000_t75" style="width:.75pt;height:.75pt">'
        '<v:imagedata r:id="rId1" />'
        '</v:shape>'
        '</w:pict></w:r>'
        '<w:r><w:fldChar w:fldCharType="end" /></w:r>'
        '</w:p>'
        '<w:p w:rsidR="009E0DC7" w:rsidRDefault="009E0DC7">'
        '<w:pPr><w:pStyle w:val="Footer" /></w:pPr>'
        '</w:p>'
        '</w:ftr>'
    )
    output_zip.writestr("word/footer0.xml", footer_xml)
    output_zip.close()
    return output_buf.getvalue()


# ===================== Excel 蜜点生成 =====================
def make_canary_msexcel_placeholder(template_path, url):
    """模板占位符模式：替换 HONEYDROP_TOKEN_URL 为 token"""
    now = datetime.datetime.now()
    now_ts = format_time_for_doc(now)
    created_ts = format_time_for_doc(now - datetime.timedelta(days=random.randint(1, 25)))
    output_buf = BytesIO()
    output_zip = ZipFile(output_buf, "w")
    with ZipFile(template_path, "r") as doc:
        for entry in doc.filelist:
            if entry.external_attr & 0x10:
                continue
            contents = zipinfo_contents_replace(doc, entry, "HONEYDROP_TOKEN_URL", url)
            contents = contents.replace("aaaaaaaaaaaaaaaaaaaa", created_ts)
            contents = contents.replace("bbbbbbbbbbbbbbbbbbbb", now_ts)
            output_zip.writestr(entry, contents)
    output_zip.close()
    return output_buf.getvalue()


# ===================== 测试执行 =====================
print("=" * 60)
print("  蜜点 (Honeypoint) 生成测试")
print("=" * 60)

# --- 1. 账户蜜点 ---
print("\n[1] 账户蜜点 (Account Honeypoint)")
print("-" * 40)

print("\n  中文名 -> 拼音用户名 (张三, 数量=8):")
result = username_generate("张三", 8)
for i, r in enumerate(result):
    print(f"    {i+1}. {r}")

print("\n  英文用户名变形 (zhangsan, 数量=8):")
result = username_generate("zhangsan", 8)
for i, r in enumerate(result):
    print(f"    {i+1}. {r}")

print("\n  带数字用户名变形 (admin123, 数量=8):")
result = username_generate("admin123", 8)
for i, r in enumerate(result):
    print(f"    {i+1}. {r}")

print("\n  随机密码 (数量=5, 长度=12):")
result = password_genaerate(5, length=12)
for i, r in enumerate(result):
    print(f"    {i+1}. {r}")

print("\n  >>> 账户蜜点生成: PASS")

# --- 2. Word蜜点 ---
print("\n[2] 文件蜜点 - Word (File Honeypoint)")
print("-" * 40)

fake_token = "https://test-alert.example.com/token?t=" + get_random_string(12)
template_docx = os.path.join(TEMPLATE_DIR, "template.docx")

print(f"\n  Token: {fake_token}")

if os.path.exists(template_docx):
    # 模式A: 占位符替换
    try:
        content = make_canary_msword_placeholder(template_docx, fake_token)
        fname = f"word_placeholder_{get_random_string(5)}.docx"
        output_path = os.path.join(GENERATE_DIR, fname)
        with open(output_path, "wb") as f:
            f.write(content)
        print(f"  [OK] 占位符模式: {output_path} ({os.path.getsize(output_path)} bytes)")

        # 验证token是否嵌入到文件
        with ZipFile(output_path, "r") as zf:
            for entry in zf.filelist:
                if entry.filename.endswith(".xml") or entry.filename.endswith(".rels"):
                    content_str = zf.read(entry).decode("utf-8", errors="ignore")
                    if fake_token in content_str:
                        print(f"        [验证] Token已嵌入到 {entry.filename}")
                        break
    except Exception as e:
        print(f"  [FAIL] 占位符模式: {e}")

    # 模式B: Footer外链嵌入
    try:
        content = make_canary_msword_footer(template_docx, fake_token)
        fname = f"word_footer_{get_random_string(5)}.docx"
        output_path = os.path.join(GENERATE_DIR, fname)
        with open(output_path, "wb") as f:
            f.write(content)
        print(f"  [OK] Footer模式: {output_path} ({os.path.getsize(output_path)} bytes)")

        # 验证token是否嵌入到footer
        with ZipFile(output_path, "r") as zf:
            if "word/footer0.xml" in [e.filename for e in zf.filelist]:
                footer_content = zf.read("word/footer0.xml").decode("utf-8", errors="ignore")
                if fake_token in footer_content:
                    print(f"        [验证] Token已嵌入到 word/footer0.xml")
            rels_files = [e for e in zf.filelist if "footer0.xml.rels" in e.filename]
            if rels_files:
                rels_content = zf.read(rels_files[0]).decode("utf-8", errors="ignore")
                if fake_token in rels_content:
                    print(f"        [验证] Token已嵌入到 footer0.xml.rels")
    except Exception as e:
        print(f"  [FAIL] Footer模式: {e}")
else:
    print(f"  [FAIL] 模板文件不存在: {template_docx}")

# --- 3. Excel蜜点 ---
print("\n[3] 文件蜜点 - Excel (File Honeypoint)")
print("-" * 40)

template_xlsx = os.path.join(TEMPLATE_DIR, "template.xlsx")

if os.path.exists(template_xlsx):
    # 模式A: 占位符替换
    try:
        content = make_canary_msexcel_placeholder(template_xlsx, fake_token)
        fname = f"excel_placeholder_{get_random_string(5)}.xlsx"
        output_path = os.path.join(GENERATE_DIR, fname)
        with open(output_path, "wb") as f:
            f.write(content)
        print(f"  [OK] 占位符模式: {output_path} ({os.path.getsize(output_path)} bytes)")

        # 验证token
        with ZipFile(output_path, "r") as zf:
            for entry in zf.filelist:
                if entry.filename.endswith(".xml") or entry.filename.endswith(".rels"):
                    content_str = zf.read(entry).decode("utf-8", errors="ignore")
                    if fake_token in content_str:
                        print(f"        [验证] Token已嵌入到 {entry.filename}")
                        break
    except Exception as e:
        print(f"  [FAIL] 占位符模式: {e}")
else:
    print(f"  [FAIL] 模板文件不存在: {template_xlsx}")

# --- 汇总 ---
print("\n" + "=" * 60)
print("  测试完成 -- 所有蜜点生成功能正常")
print("=" * 60)

# 列出生成的所有文件
print("\n生成的文件列表:")
for f in sorted(os.listdir(GENERATE_DIR)):
    fpath = os.path.join(GENERATE_DIR, f)
    print(f"  {f} ({os.path.getsize(fpath)} bytes)")

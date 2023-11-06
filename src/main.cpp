
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>

#include <string>
using namespace std;

#include <cJSON.h>
#include <lz4.h>
#include <sha2.h>
#include <Base64.h>

#include <sqlite3.h>

/*
    Search相关.
*/
void parse_search_json_lz4(const char * json_lz4_path);
void print_search_json(cJSON * root);
void print_search_hash(const char * value);

char g_firefox_config_dir[128] = {0};

/*
    homepage相关.
*/
void parse_prefs_js(const char * prefs_path,const char *key);

/*
    历史记录相关.
*/
void parse_history_firefox(const char * places_path);

int
main(int argc,char **argv)
{
    printf("======  测试Firefox-Search_MacOS版本   ======\r\n");
    strcpy(g_firefox_config_dir,"ssfvl7o4.default-release");
    parse_search_json_lz4("./test/search.json.mozlz4_macos");
    
    printf("\r\n======  测试Firefox-Search_Windows版本    ======\r\n");
    memset(g_firefox_config_dir,0,128);
    strcpy(g_firefox_config_dir,"ugxojpzr.default-release");
    parse_search_json_lz4("./test/search.json.mozlz4_win");

    printf("\r\n======  测试Firefox-Homepage    ======\r\n");
    parse_prefs_js("./test/prefs.js","browser.startup.homepage");

    printf("\r\n======  测试Firefox-History    ======\r\n");
    parse_history_firefox("./test/places.sqlite");

    return 0;
}

void parse_search_json_lz4(const char * json_lz4_path)
{
    FILE * file = NULL;
	char * json_buf_lz4 = NULL;
	char * json_buf = NULL;
    cJSON * root = NULL;

	uint32_t file_len = 0;
	uint32_t read_len = 0;
	uint32_t src_len = 0;

	char magic[16] = { 0 };

	file = fopen(json_lz4_path, "rb");
	if (NULL == file)
	{
        printf("fopen(%s) error %d\r\n",json_lz4_path,errno);
		return;
	}

	//获取文件总长度.
	fseek(file, 0, SEEK_END);
	file_len = ftell(file);

	fseek(file, 0, SEEK_SET);

    printf("File len %d\r\n",file_len);

    //读取8字节magic.
	read_len = fread(magic, 1,8, file);
	file_len = file_len - read_len;

	read_len = fread(&src_len, 1, sizeof(src_len), file);
	file_len = file_len - read_len;

    printf("File json_buf_lz4_len %d\r\n",file_len);
    printf("File json_buf_len %d\r\n",src_len);

	json_buf_lz4 = (char*)malloc(sizeof(char)*file_len);
	if (NULL != json_buf_lz4)
	{
		memset(json_buf_lz4, 0, file_len);
		read_len = fread(json_buf_lz4, file_len, 1, file);

		json_buf = (char*)malloc(sizeof(char) * src_len);
		if (NULL != json_buf)
		{
			memset(json_buf, 0, src_len);

            //lz4解压.
			int d_lne = LZ4_decompress_fast(json_buf_lz4, json_buf, src_len);
			if (d_lne == file_len)
			{
                printf("\r\n[Search_JSON] \r\n %s \r\n",json_buf);
				root = cJSON_Parse(json_buf);
                if(NULL != root)
                {
                    print_search_json(root);

                    cJSON_Delete(root);
                    root = NULL;
                }
                else
                {
                    printf("cJSON_Parse() error\r\n");
                }
			}
		}
	}

	if (NULL != json_buf)
	{
		free(json_buf);
		json_buf = NULL;
	}

	if (NULL != json_buf_lz4)
	{
		free(json_buf_lz4);
		json_buf_lz4 = NULL;
	}

	fclose(file);
	file = NULL;
}

void print_search_json(cJSON * root)
{
    cJSON * engines = cJSON_GetObjectItem(root,"engines");
    if(NULL != engines)
    {
        int count = cJSON_GetArraySize(engines);
        printf("\r\nEngines count = %d\r\n",count);

        for(int index = 0; index < count; index++)
        {
            cJSON * item = cJSON_GetArrayItem(engines,index);
            if(NULL != item)
            {
                cJSON * json_id = cJSON_GetObjectItem(item,"id");
                cJSON * json_name = cJSON_GetObjectItem(item,"_name");

                printf("Engine [%d of %d] {id} %s,{name} %s\r\n",
                    index + 1,count,
                    json_id->valuestring,
                    json_name->valuestring);
            }
        }
    }
    else
    {
        printf("\r\nEngines count = %d\r\n",0);
    }

    cJSON * metaData = cJSON_GetObjectItem(root,"metaData");
    if(NULL != metaData)
    {
        cJSON * defaultEngineId_json = cJSON_GetObjectItem(metaData,"defaultEngineId");
        cJSON * defaultEngineIdHash_json = cJSON_GetObjectItem(metaData,"defaultEngineIdHash");
        cJSON * appDefaultEngine_json = cJSON_GetObjectItem(metaData,"appDefaultEngine");
        
        printf("\r\nEngine default id %s,IdHash %s,name %s\r\n",
            defaultEngineId_json->valuestring,
            defaultEngineIdHash_json->valuestring,
            appDefaultEngine_json?appDefaultEngine_json->valuestring:"{NULL}");
        
        print_search_hash(defaultEngineId_json->valuestring);
    }
}

void print_search_hash(const char * value)
{
    char disclaimer[4096] = {0};

    strcpy(disclaimer,"By modifying this file, I agree that I am doing so ");
    strcat(disclaimer,"only within Firefox itself, using official, user-driven search ");
    strcat(disclaimer,"engine selection processes, and in a way which does not circumvent ");
    strcat(disclaimer,"user consent. I acknowledge that any attempt to change this file ");
    strcat(disclaimer,"from outside of Firefox is a malicious act, and will be responded ");
    strcat(disclaimer,"to accordingly.");

    uint32_t all_len = strlen(g_firefox_config_dir) + strlen(disclaimer) + strlen(value) + 1;

    //三部分数据.
    char * all_ = (char*)malloc(all_len);

    memset(all_,0,all_len);
    strcpy(all_,g_firefox_config_dir);
    strcat(all_,value);
    strcat(all_,disclaimer);

    //sha256.
    sha256_ctx ctx;
    unsigned char digest[32] = {0};

    sha256_init(&ctx);
    sha256_update(&ctx, (const unsigned char*)all_, strlen(all_));
    sha256_final(&ctx, digest);

    free(all_);
    all_ = NULL;

    //Base64编码.
    char base64_encode_text[128] = {0};
    size_t out_len = 0;

    encode_base64((char*)digest,32,base64_encode_text,128,&out_len);

    printf("[Hash_now] %s\r\n",base64_encode_text);
}

void get_pref_text(const char * pref_path, string & pref_str)
{
	FILE * file = NULL;
	char * pref_buf = NULL;
	long pref_len = 0;

	file = fopen(pref_path, "rb");
	if (NULL == file)
	{
		return;
	}

	fseek(file, 0, SEEK_END);

	pref_len = ftell(file);
	pref_len = pref_len + 1;

	fseek(file, 0, SEEK_SET);

	pref_buf = (char*)malloc(pref_len);
	if (NULL == pref_buf)
	{
		fclose(file);
		file = NULL;

		return;
	}

	memset(pref_buf, 0, pref_len);
	fread(pref_buf, pref_len, 1, file);
	pref_str = pref_buf;

	free(pref_buf);
	pref_buf = NULL;

	fclose(file);
	file = NULL;
}

void parse_prefs_js(const char * prefs_path,const char *prefs_key)
{
    string real_key = "";
	string value = "";
	string pref_str = "";

	get_pref_text(prefs_path, pref_str);

	real_key = "user_pref(\"";
	real_key = real_key + prefs_key;
	real_key = real_key + "\", \"";
	
	int pos_1 = pref_str.find(real_key);
	int pos_2 = -1;
	if (-1 != pos_1)
	{
		pos_2 = pref_str.find("\"",pos_1 + real_key.length());
		if (-1 != pos_2)
		{
			value = pref_str.substr(pos_1 + real_key.length(),pos_2 - pos_1 - real_key.length());
		}
	}

	printf("\r\n {Key} %s,{Value} %s \r\n",prefs_key,value.c_str());
}

void parse_history_firefox(const char * places_path)
{
    printf("\r\n[[Sqlite3_Version : %s]]\r\n",sqlite3_libversion());

    sqlite3 * db = NULL;
    char * err_msg = NULL;
    char * sql_history = "select a.id, \
                            b.url, \
                            b.title, \
                            strftime('%Y-%m-%d %H:%M:%S', a.visit_date/1000000.0, 'unixepoch', 'localtime') as v_date, \
                            a.visit_type \
                            from moz_historyvisits a,moz_places b \
                            where a.place_id = b.id \
                            and b.title like '%'\
                            order by v_date desc";

    int ret_code = sqlite3_open(places_path,&db);
    if(SQLITE_OK != ret_code)
    {
        printf("sqlite3_open(%s) error %s\r\n",places_path,sqlite3_errmsg(db));
        sqlite3_close(db);

        return;
    }

    char **result;
    int nrows, ncolumns, i, j, index;

    ret_code = sqlite3_get_table(db, sql_history, &result, &nrows, &ncolumns, &err_msg);
    if(SQLITE_OK != ret_code)
    {
        printf("sqlite3_get_table() error : %s\r\n",err_msg);
        sqlite3_free(err_msg);
    }
 
    index = ncolumns;
    for (i = 0; i < nrows; i++)
    {
        for (j = 0; j < ncolumns; j++)
        {
            printf("%-8s : %-8s\n", result[j], result[index]);   
            index++;
        }

        printf("************************\n");
    }

    sqlite3_free_table(result);

    sqlite3_close(db);
    db = NULL;
}

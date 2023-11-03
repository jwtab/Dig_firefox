
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>

#include <cJSON.h>
#include <lz4.h>
#include <sha2.h>
#include <Base64.h>

/*
    Search相关.
*/
void parse_search_json_lz4(const char * json_lz4_path);
void print_search_json(cJSON * root);
void print_search_hash(const char * value);

char g_firefox_config_dir[2048] = {0};

int
main(int argc,char **argv)
{
    parse_search_json_lz4("./test/search.json.mozlz4_macos");
    strcpy(g_firefox_config_dir,"ssfvl7o4.default-release");
    //strcpy(g_firefox_config_dir,"/Users/joyce/Library/Application Support/Firefox/Profiles/ssfvl7o4.default-release");
    
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

        printf("\r\nEngine default id %s,IdHash %s\r\n",
            defaultEngineId_json->valuestring,
            defaultEngineIdHash_json->valuestring);
        
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

    char base64_encode_text[128] = {0};
    size_t out_len = 0;

    encode_base64((char*)digest,32,base64_encode_text,128,&out_len);

    printf("[Hash_now] %s\r\n",base64_encode_text);
}

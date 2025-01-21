#include <jansson.h>
#include <stdio.h>

int main() {
    // 创建一个 JSON 对象
    json_t *json_obj = json_object();  // 使用不同的变量名
    if (!json_obj) {
        fprintf(stderr, "Failed to create JSON object\n");
        return 1;
    }

    // 添加键值对
    json_object_set_new(json_obj, "name", json_string("Alice"));
    json_object_set_new(json_obj, "age", json_integer(30));
    json_object_set_new(json_obj, "tall", json_real(172.98));
    json_object_set_new(json_obj, "girlfriend", json_null());

    // 创建一个 JSON 数组并添加到对象中
    json_t *score_array = json_array();
    json_array_append_new(score_array, json_integer(22));
    json_array_append_new(score_array, json_integer(1));
    json_array_append_new(score_array, json_integer(103));
    json_object_set_new(json_obj, "score", score_array);

    // 打印初始 JSON 字符串
    char *json_str = json_dumps(json_obj, JSON_INDENT(4));
    printf("Initial JSON:\n%s\n", json_str);
    free(json_str);

    // 删除 "girlfriend" 字段
    json_object_del(json_obj, "girlfriend"); // 删除 "girlfriend" 字段

    // 修改 "name" 的值
    json_object_set(json_obj, "name", json_string("Bob")); // 修改名字为 Bob

    // 打印修改后的 JSON 字符串
    json_str = json_dumps(json_obj, JSON_INDENT(4));
    printf("Modified JSON:\n%s\n", json_str);
    free(json_str);

    // 释放内存
    json_decref(json_obj);

    return 0;
}

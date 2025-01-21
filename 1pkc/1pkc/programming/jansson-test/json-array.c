#include <jansson.h>
#include <stdio.h>

int main() {
    // 创建一个 JSON 数组
    json_t *json_arr = json_array(); // 使用不同的变量名
    if (!json_arr) {
        fprintf(stderr, "Failed to create JSON array\n");
        return 1;
    }

    // 添加不同类型的元素
    json_array_append_new(json_arr, json_string("Hello")); // 字符串
    json_array_append_new(json_arr, json_integer(42));     // 整数
    json_array_append_new(json_arr, json_real(3.14));      // 浮点数
    json_array_append_new(json_arr, json_true());           // 布尔值
    json_array_append_new(json_arr, json_null());           // null

    // 打印初始 JSON 数组
    char *json_str = json_dumps(json_arr, JSON_INDENT(4));
    printf("Initial JSON Array:\n%s\n", json_str);
    free(json_str);

    // 在索引 1 处插入新元素
    json_array_insert_new(json_arr, 1, json_string("Inserted")); // 在索引 1 处插入字符串

    // 打印修改后的 JSON 数组
    json_str = json_dumps(json_arr, JSON_INDENT(4));
    printf("After insertion JSON Array:\n%s\n", json_str);
    free(json_str);

    // 删除元素
    json_array_remove(json_arr, 3); // 删除索引为 3 的元素 (布尔值)
    json_str = json_dumps(json_arr, JSON_INDENT(4));
    printf("After removal JSON Array:\n%s\n", json_str);
    free(json_str);

    // 查询元素
    json_t *value = json_array_get(json_arr, 1); // 获取索引为 1 的元素
    if (json_is_integer(value)) {
        printf("Element at index 1: %lld\n", json_integer_value(value));
    }

    // 修改元素
    json_array_set(json_arr, 2, json_string("Modified")); // 修改索引为 2 的元素
    json_str = json_dumps(json_arr, JSON_INDENT(4));
    printf("Modified JSON Array:\n%s\n", json_str);
    free(json_str);

    // 释放内存
    json_decref(json_arr);

    return 0;
}

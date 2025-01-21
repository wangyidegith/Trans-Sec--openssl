#include <jansson.h>
#include <stdio.h>

int main() {
    const char *json_text = "{\"name\": \"Alice\", \"age\": 30, \"tall\": 172.98, \"girlfriend\": null, \"score\": [22, 1, 103]}";
    
    json_error_t error;
    json_t *root = json_loads(json_text, 0, &error);
    
    // 检查解析是否成功
    if (!root) {
        fprintf(stderr, "Error: on line %d, column %d: %s\n", 
                error.line, error.column, error.text);
        return 1;
    }
    
    // 获取并打印各个字段的值
    json_t *name = json_object_get(root, "name");
    json_t *age = json_object_get(root, "age");
    json_t *tall = json_object_get(root, "tall");
    json_t *girlfriend = json_object_get(root, "girlfriend");
    json_t *score = json_object_get(root, "score");

    if (json_is_string(name)) {
        printf("Name: %s\n", json_string_value(name));
    }

    if (json_is_integer(age)) {
        printf("Age: %lld\n", json_integer_value(age));  // 使用 %lld
    }

    if (json_is_real(tall)) {
        printf("Tall: %.2f\n", json_real_value(tall));
    }

    if (json_is_null(girlfriend)) {
        printf("Girlfriend: null\n");
    }

    if (json_is_array(score)) {
        printf("Score: ");
        size_t index;
        json_t *value;
        json_array_foreach(score, index, value) {   // json_t* json_array_get(const json_t* object, size_t index);
            printf("%lld ", json_integer_value(value));  // 使用 %lld
        }
        printf("\n");
    }

    // 释放内存
    json_decref(root);
    
    return 0;
}

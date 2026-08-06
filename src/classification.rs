pub const CATEGORY_VERSION: i64 = 1;

struct CategoryRule {
    name: &'static str,
    keywords: &'static [(&'static str, u16)],
}

const CATEGORY_RULES: &[CategoryRule] = &[
    CategoryRule {
        name: "海报设计",
        keywords: &[
            ("海报", 100),
            ("poster", 100),
            ("招贴", 100),
            ("flyer", 100),
            ("宣传页", 90),
            ("宣传画", 90),
            ("banner", 90),
            ("封面", 75),
            ("长图", 70),
            ("信息图", 90),
            ("infographic", 90),
            ("排版设计", 70),
        ],
    },
    CategoryRule {
        name: "UI/网页",
        keywords: &[
            ("用户界面", 100),
            ("user interface", 100),
            ("app界面", 100),
            ("小程序界面", 100),
            ("网页设计", 100),
            ("web design", 100),
            ("landing page", 100),
            ("dashboard", 95),
            ("ui", 90),
            ("ux", 80),
            ("界面", 75),
            ("控制台", 70),
            ("交互设计", 75),
            ("网站首页", 85),
        ],
    },
    CategoryRule {
        name: "产品电商",
        keywords: &[
            ("商品主图", 100),
            ("产品主图", 100),
            ("电商", 100),
            ("详情页", 100),
            ("产品图", 95),
            ("product photography", 95),
            ("白底图", 90),
            ("商品", 80),
            ("产品", 80),
            ("product", 80),
            ("包装", 70),
            ("packaging", 70),
            ("商业摄影", 65),
            ("commercial photography", 65),
        ],
    },
    CategoryRule {
        name: "品牌视觉",
        keywords: &[
            ("品牌视觉", 100),
            ("品牌设计", 100),
            ("brand identity", 100),
            ("视觉识别", 95),
            ("vi设计", 95),
            ("logo", 100),
            ("标志设计", 100),
            ("字标", 90),
            ("字体设计", 80),
            ("品牌", 65),
            ("brand", 65),
        ],
    },
    CategoryRule {
        name: "插画动漫",
        keywords: &[
            ("插画", 100),
            ("illustration", 100),
            ("二次元", 100),
            ("动漫", 100),
            ("anime", 100),
            ("漫画", 95),
            ("comic", 95),
            ("卡通", 90),
            ("cartoon", 90),
            ("绘本", 90),
            ("像素画", 90),
            ("pixel art", 90),
            ("概念艺术", 85),
            ("concept art", 85),
            ("数字艺术", 75),
            ("digital art", 75),
            ("水彩", 65),
            ("watercolor", 65),
            ("油画", 65),
            ("oil painting", 65),
            ("国风", 60),
        ],
    },
    CategoryRule {
        name: "人像写真",
        keywords: &[
            ("人像", 100),
            ("portrait", 100),
            ("写真", 95),
            ("自拍", 90),
            ("selfie", 90),
            ("模特", 80),
            ("model shoot", 85),
            ("证件照", 95),
            ("婚纱照", 95),
            ("人物摄影", 90),
            ("人物", 55),
            ("女性", 50),
            ("男性", 50),
            ("女孩", 50),
            ("男孩", 50),
            ("少女", 55),
            ("青年", 45),
        ],
    },
    CategoryRule {
        name: "美食饮品",
        keywords: &[
            ("美食", 100),
            ("food photography", 100),
            ("菜品", 95),
            ("餐饮", 90),
            ("食物", 90),
            ("food", 90),
            ("甜点", 90),
            ("dessert", 90),
            ("饮品", 85),
            ("beverage", 85),
            ("料理", 85),
            ("烘焙", 80),
            ("蛋糕", 75),
            ("咖啡", 65),
            ("茶饮", 75),
            ("鸡尾酒", 75),
        ],
    },
    CategoryRule {
        name: "动物宠物",
        keywords: &[
            ("动物", 100),
            ("animal", 100),
            ("宠物", 100),
            ("pet", 100),
            ("猫咪", 95),
            ("小猫", 95),
            ("橘猫", 90),
            ("狸花猫", 90),
            ("布偶猫", 90),
            ("宠物猫", 90),
            ("一只猫", 90),
            ("cat", 90),
            ("狗狗", 95),
            ("小狗", 95),
            ("柴犬", 90),
            ("柯基", 90),
            ("金毛", 90),
            ("宠物狗", 90),
            ("一只狗", 90),
            ("dog", 90),
            ("小鸟", 80),
            ("飞鸟", 80),
            ("鸟类", 80),
            ("鹦鹉", 80),
            ("bird", 80),
            ("兔子", 85),
            ("rabbit", 85),
            ("马匹", 75),
            ("骏马", 75),
            ("白马", 75),
            ("horse", 75),
            ("熊猫", 90),
            ("panda", 90),
        ],
    },
    CategoryRule {
        name: "风景建筑",
        keywords: &[
            ("风景", 100),
            ("landscape", 100),
            ("建筑", 100),
            ("architecture", 100),
            ("室内设计", 100),
            ("interior design", 100),
            ("城市景观", 95),
            ("cityscape", 95),
            ("街景", 85),
            ("山川", 85),
            ("森林", 80),
            ("海边", 80),
            ("自然风光", 95),
            ("旅行摄影", 85),
            ("房间", 60),
            ("客厅", 70),
            ("卧室", 70),
            ("庭院", 75),
            ("日落", 60),
        ],
    },
    CategoryRule {
        name: "科技概念",
        keywords: &[
            ("科技", 100),
            ("technology", 100),
            ("科幻", 95),
            ("sci-fi", 95),
            ("science fiction", 95),
            ("赛博朋克", 95),
            ("cyberpunk", 95),
            ("机器人", 90),
            ("robot", 90),
            ("太空", 85),
            ("space", 85),
            ("未来主义", 85),
            ("futuristic", 85),
            ("机甲", 90),
            ("全息", 75),
        ],
    },
    CategoryRule {
        name: "生活摄影",
        keywords: &[
            ("生活方式", 100),
            ("lifestyle", 100),
            ("纪实摄影", 95),
            ("documentary photography", 95),
            ("街拍", 90),
            ("street photography", 90),
            ("婚礼", 85),
            ("wedding", 85),
            ("运动摄影", 90),
            ("sports photography", 90),
            ("汽车摄影", 90),
            ("automotive photography", 90),
            ("静物摄影", 90),
            ("still life", 90),
            ("家居", 70),
            ("旅行", 65),
        ],
    },
    CategoryRule {
        name: "3D 设计",
        keywords: &[
            ("3d", 100),
            ("三维", 100),
            ("cgi", 100),
            ("c4d", 100),
            ("blender", 100),
            ("三维建模", 100),
            ("3d render", 100),
            ("黏土风", 85),
            ("粘土风", 85),
            ("clay render", 85),
            ("建模", 80),
            ("渲染", 55),
            ("render", 55),
        ],
    },
];

pub fn classify_prompt(prompt: &str) -> &'static str {
    let normalized = prompt.to_lowercase();
    CATEGORY_RULES
        .iter()
        .map(|rule| {
            let (strongest, total) = rule.keywords.iter().fold(
                (0_u16, 0_u32),
                |(strongest, total), (keyword, weight)| {
                    if contains_keyword(&normalized, keyword) {
                        (strongest.max(*weight), total + u32::from(*weight))
                    } else {
                        (strongest, total)
                    }
                },
            );
            (rule.name, strongest, total)
        })
        .max_by_key(|(_, strongest, total)| (*strongest, *total))
        .filter(|(_, strongest, _)| *strongest > 0)
        .map_or("其他", |(name, _, _)| name)
}

pub fn category_rank(category: &str) -> usize {
    CATEGORY_RULES
        .iter()
        .position(|rule| rule.name == category)
        .unwrap_or(CATEGORY_RULES.len())
}

fn contains_keyword(text: &str, keyword: &str) -> bool {
    if !keyword
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == ' ')
    {
        return text.contains(keyword);
    }
    text.match_indices(keyword).any(|(start, matched)| {
        let before = text[..start].chars().next_back();
        let after = text[start + matched.len()..].chars().next();
        !before.is_some_and(|character| character.is_ascii_alphanumeric())
            && !after.is_some_and(|character| character.is_ascii_alphanumeric())
    })
}

#[cfg(test)]
mod tests {
    use super::{category_rank, classify_prompt};

    #[test]
    fn prioritizes_explicit_output_type() {
        assert_eq!(classify_prompt("护肤产品成分科普长图海报"), "海报设计");
        assert_eq!(classify_prompt("电商护肤产品白底主图"), "产品电商");
        assert_eq!(
            classify_prompt("mobile app dashboard user interface"),
            "UI/网页"
        );
    }

    #[test]
    fn classifies_subjects_and_visual_styles() {
        assert_eq!(classify_prompt("一只在咖啡杯旁打盹的橘猫"), "动物宠物");
        assert_eq!(classify_prompt("写实女性人像摄影"), "人像写真");
        assert_eq!(
            classify_prompt("cinematic mountain landscape at sunset"),
            "风景建筑"
        );
        assert_eq!(classify_prompt("二次元女孩插画"), "插画动漫");
        assert_eq!(
            classify_prompt("3D abstract fluid render in Blender"),
            "3D 设计"
        );
    }

    #[test]
    fn ascii_keywords_require_word_boundaries() {
        assert_eq!(classify_prompt("a happy orange cat"), "动物宠物");
        assert_eq!(classify_prompt("unmapped abstract request"), "其他");
    }

    #[test]
    fn keeps_category_order_stable() {
        assert!(category_rank("海报设计") < category_rank("其他"));
    }
}

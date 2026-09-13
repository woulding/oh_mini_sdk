/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <map>
#include <vector>
#include <unistd.h>
#include "hyphenation.h"
#include "hyphenation_test.h"

using namespace OHOS::I18N;
using testing::ext::TestSize;
using namespace std;
using namespace testing;

namespace OHOS {
namespace I18N {
class HyphenationTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
};

void HyphenationTest::SetUp()
{
}

void HyphenationTest::TearDown()
{
}

/**
 * @tc.name: HyphenationTest001
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest001, TestSize.Level1)
{
    const char* alocale = "bg";
    Hyphenation* hyphen = Hyphenation::CreateInstance(alocale);
    auto result = hyphen->GetBreakCandidate("България"); //Бъл-га-рия
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[5], 1);
    result = hyphen->GetBreakCandidate("алгоритъм"); // ал-го-ри-тъм
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("майка"); // май-ка
    EXPECT_EQ(result[3], 1);
    result = hyphen->GetBreakCandidate("речник"); // реч-ник
    EXPECT_EQ(result[3], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest002
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest002, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("da");
    auto result = hyphen->GetBreakCandidate("stavelse"); // sta-vel-se
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("afbryderknappen"); // afbryderk-nap-pen
    EXPECT_EQ(result[9], 1);
    EXPECT_EQ(result[12], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest003
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest003, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("de");
    auto result = hyphen->GetBreakCandidate("Wörterbuch"); // Wör-ter-buch
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("Ärmel"); // Är-mel
    EXPECT_EQ(result[2], 1);
    result = hyphen->GetBreakCandidate("Übermut"); // Über-mut
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("Außenseiter"); // Au-ßen-sei-ter
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[5], 1);
    EXPECT_EQ(result[8], 1);
    result = hyphen->GetBreakCandidate("schließen"); // schlie-ßen
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("Katze"); // Kat-ze
    EXPECT_EQ(result[3], 1);
    result = hyphen->GetBreakCandidate("Ecke"); // Ecke
    EXPECT_EQ(result[2], 0);
    result = hyphen->GetBreakCandidate("Donaudampfschifffahrt"); // Do-nau-dampf-schiff-fahrt
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[5], 1);
    EXPECT_EQ(result[10], 1);
    EXPECT_EQ(result[16], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest004
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest004, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("en-GB");
    auto result = hyphen->GetBreakCandidate("dictionary"); // dic-tion-ary
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[7], 1);
    result = hyphen->GetBreakCandidate("colour"); // col-our
    EXPECT_EQ(result[3], 1);
    result = hyphen->GetBreakCandidate("well-known"); // well-known
    EXPECT_EQ(result[5], 2);
    result = hyphen->GetBreakCandidate("accommodate"); // ac-com-mod-ate
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[5], 1);
    EXPECT_EQ(result[8], 1);
    result = hyphen->GetBreakCandidate("university"); // uni-ver-sity
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("however"); // how-ever
    EXPECT_EQ(result[3], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest005
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest005, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("en-US");
    auto result = hyphen->GetBreakCandidate("dictionary"); // dic-tio-nary
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("color"); // color
    EXPECT_EQ(result[0], 0);
    EXPECT_EQ(result[1], 0);
    EXPECT_EQ(result[2], 0);
    EXPECT_EQ(result[3], 0);
    EXPECT_EQ(result[4], 0);
    result = hyphen->GetBreakCandidate("well-known"); // well-known
    EXPECT_EQ(result[5], 2);
    result = hyphen->GetBreakCandidate("analyze"); // an-a-lyze
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[3], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest006
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest006, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("es");
    auto result = hyphen->GetBreakCandidate("llamar"); // lla-mar
    EXPECT_EQ(result[3], 1);
    result = hyphen->GetBreakCandidate("mucho"); // mu-cho
    EXPECT_EQ(result[2], 1);
    result = hyphen->GetBreakCandidate("diccionario"); // dic-cio-na-rio
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[6], 1);
    EXPECT_EQ(result[8], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest007
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest007, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("fr");
    auto result = hyphen->GetBreakCandidate("dictionnaire"); // dic-tion-naire
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[7], 1);
    result = hyphen->GetBreakCandidate("d'accord"); // d'ac-cord
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("téléphone"); // té-lé-phone
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("antiarché"); // an-ti-ar-ché
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[4], 1);
    EXPECT_EQ(result[6], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest008
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest008, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("hr");
    auto result = hyphen->GetBreakCandidate("rječnik"); // rječ-nik
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("algoritam"); // al-go-ri-tam
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[4], 1);
    EXPECT_EQ(result[6], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest009
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest009, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("lt");
    auto result = hyphen->GetBreakCandidate("kompiuteris"); // kom-piu-te-ris
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[6], 1);
    EXPECT_EQ(result[8], 1);
    result = hyphen->GetBreakCandidate("skiemuo"); // skie-muo
    EXPECT_EQ(result[4], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest010
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest010, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("pl");
    auto result = hyphen->GetBreakCandidate("półach"); // pó-łach
    EXPECT_EQ(result[2], 1);
    result = hyphen->GetBreakCandidate("komputer"); // kom-pu-ter
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[5], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest011
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest011, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("pt");
    auto result = hyphen->GetBreakCandidate("hardware"); // hard-ware
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("software"); // soft-ware
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("bênção"); // bên-ção
    EXPECT_EQ(result[3], 1);
    result = hyphen->GetBreakCandidate("dicionário"); // di-cio-ná-rio
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[5], 1);
    EXPECT_EQ(result[7], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest012
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest012, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("sl");
    auto result = hyphen->GetBreakCandidate("računalnik"); // ra-ču-nal-nik
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[4], 1);
    EXPECT_EQ(result[7], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest013
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest013, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("be");
    auto result = hyphen->GetBreakCandidate("Беларусь"); // Бе-ла-русь
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("камп'ютар"); // ка-мп'ю-тар
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("выязычэнне"); // вы-язы-чэн-не
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[5], 1);
    EXPECT_EQ(result[8], 1);
    result = hyphen->GetBreakCandidate("навукова"); // на-ву-ко-ва
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[4], 1);
    EXPECT_EQ(result[6], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest014
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest014, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("nl");
    auto result = hyphen->GetBreakCandidate("Streuexperiment"); // Streu-experi-ment
    EXPECT_EQ(result[5], 1);
    EXPECT_EQ(result[11], 1);
    result = hyphen->GetBreakCandidate("STREUEXPERIMENT"); // STREU-EXPERI-MENT
    EXPECT_EQ(result[5], 1);
    EXPECT_EQ(result[11], 1);
    result = hyphen->GetBreakCandidate("AIOUEKIOUAE"); // AIOUE-KIOUAE
    EXPECT_EQ(result[5], 1);
    result = hyphen->GetBreakCandidate("Iouëloaae"); // Iouë-loaae
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("Egostischoïsch"); // Egostischo-ïsch
    EXPECT_EQ(result[10], 1);
    result = hyphen->GetBreakCandidate("EGCÜHSËECH"); // EGC-ÜHS-ËECH
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("aandachtstrekkers"); // aan-dachts-trek-kers
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[9], 1);
    EXPECT_EQ(result[13], 1);
    result = hyphen->GetBreakCandidate("onthoofdingen"); // ont-hoof-din-gen
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[7], 1);
    EXPECT_EQ(result[10], 1);
    result = hyphen->GetBreakCandidate("achtendertigste"); // acht-en-der-tig-ste
    EXPECT_EQ(result[4], 1);
    EXPECT_EQ(result[6], 1);
    EXPECT_EQ(result[9], 1);
    EXPECT_EQ(result[12], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest015
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest015, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("nl");
    auto result = hyphen->GetBreakCandidate("beschermengelen"); // be-scherm-en-ge-len
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[8], 1);
    EXPECT_EQ(result[10], 1);
    EXPECT_EQ(result[12], 1);
    result = hyphen->GetBreakCandidate("bijstandstrekkers"); // bij-stands-trek-kers
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[9], 1);
    EXPECT_EQ(result[13], 1);
    result = hyphen->GetBreakCandidate("ministersportefeuilles"); // mi-nis-ters-por-te-feuil-les
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[5], 1);
    EXPECT_EQ(result[9], 1);
    EXPECT_EQ(result[12], 1);
    EXPECT_EQ(result[14], 1);
    EXPECT_EQ(result[19], 1);
    result = hyphen->GetBreakCandidate("schilderstalent"); // schil-ders-ta-lent
    EXPECT_EQ(result[5], 1);
    EXPECT_EQ(result[9], 1);
    EXPECT_EQ(result[11], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest016
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest016, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("el");
    auto result = hyphen->GetBreakCandidate("ργδζθκλξραυστφχψ");
    EXPECT_EQ(result[8], 1);
    result = hyphen->GetBreakCandidate("Βγδαβγδαθθελστιφ");
    EXPECT_EQ(result[9], 1);
    result = hyphen->GetBreakCandidate("ργδζθκλξραϋστφχψ");
    EXPECT_EQ(result[8], 1);
    result = hyphen->GetBreakCandidate("ργδζθκλξροΫστφχψ");
    EXPECT_EQ(result[10], 1);
    result = hyphen->GetBreakCandidate("βγδζθκλξραίστφχ");
    EXPECT_EQ(result[8], 1);
    result = hyphen->GetBreakCandidate("βγδζθκλξράυστφχ");
    EXPECT_EQ(result[10], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest017
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest017, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("ru");
    auto result = hyphen->GetBreakCandidate("выиграл");
    EXPECT_EQ(result[2], 1);
    result = hyphen->GetBreakCandidate("выключена");
    EXPECT_EQ(result[2], 1);
    result = hyphen->GetBreakCandidate("Войдите");
    EXPECT_EQ(result[3], 1);
    result = hyphen->GetBreakCandidate("надежности");
    EXPECT_EQ(result[3], 1);
    result = hyphen->GetBreakCandidate("Заботьтесь");
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("объективный");
    EXPECT_EQ(result[3], 1);
    result = hyphen->GetBreakCandidate("использовать");
    result = hyphen->GetBreakCandidate("данных");
    result = hyphen->GetBreakCandidate("приложения");
    result = hyphen->GetBreakCandidate("статуса");
    EXPECT_EQ(result[2], 0);
    EXPECT_EQ(result[6], 0);
    result = hyphen->GetBreakCandidate("значок");
    EXPECT_EQ(result[5], 0);
    result = hyphen->GetBreakCandidate("Удалить");
    EXPECT_EQ(result[6], 0);
    result = hyphen->GetBreakCandidate("приложений");
    EXPECT_EQ(result[9], 0);
    result = hyphen->GetBreakCandidate("Станьтщф");
    EXPECT_EQ(result[5], 0);
    EXPECT_EQ(result[6], 0);
    EXPECT_EQ(result[7], 0);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest018
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest018, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("ka");
    auto result = hyphen->GetBreakCandidate("კრდათვრიმც");
    EXPECT_EQ(result[5], 1);
    result = hyphen->GetBreakCandidate("კრბდოყანკ");
    EXPECT_EQ(result[5], 1);
    result = hyphen->GetBreakCandidate("ატფო");
    EXPECT_EQ(result[2], 1);
    result = hyphen->GetBreakCandidate("სახლისთვის");
    EXPECT_EQ(result[6], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest019
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest019, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("it");
    auto result = hyphen->GetBreakCandidate("Asistenzauot");
    EXPECT_EQ(result[9], 1);
    result = hyphen->GetBreakCandidate("intrfacnmmtcia");
    EXPECT_EQ(result[4], 1);
    EXPECT_EQ(result[11], 1);
    result = hyphen->GetBreakCandidate("gnocchi");
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("scala");
    EXPECT_EQ(result[3], 1);
    result = hyphen->GetBreakCandidate("bachi");
    EXPECT_EQ(result[2], 1);
    result = hyphen->GetBreakCandidate("figliastro");
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("biscia");
    EXPECT_EQ(result[2], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest020
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest020, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("uk");
    auto result = hyphen->GetBreakCandidate("ийпінхастгфпінхаст");
    EXPECT_EQ(result[10], 1);
    result = hyphen->GetBreakCandidate("кільце");
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("низько"); // низь-ко
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("об’ява"); // об’-ява
    EXPECT_EQ(result[3], 1);
    result = hyphen->GetBreakCandidate("багатоступінчастий"); // багато-ступінчастий
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("восьмигранний"); // восьми-гранний
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("тупінхастий"); // тупін-хастий
    EXPECT_EQ(result[5], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest021
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest021, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("ru");
    auto result = hyphen->GetBreakCandidate("аккаунт"); // аккаунт
    EXPECT_EQ(result[5], 0);
    EXPECT_EQ(result[6], 0);
    result = hyphen->GetBreakCandidate("устройств"); // устройств
    EXPECT_EQ(result[6], 0);
    EXPECT_EQ(result[7], 0);
    EXPECT_EQ(result[8], 0);
    result = hyphen->GetBreakCandidate("получить"); // получить
    EXPECT_EQ(result[7], 0);
    result = hyphen->GetBreakCandidate("автозапуск"); // ав-то-запуск
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("большой"); // боль-шой
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("возможно"); // воз-мож-но
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("возможностей"); // воз-мож-нос-тей
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[6], 1);
    EXPECT_EQ(result[9], 1);
    result = hyphen->GetBreakCandidate("возникновении"); // воз-ник-но-ве-нии
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[6], 1);
    EXPECT_EQ(result[8], 1);
    result = hyphen->GetBreakCandidate("воспроизвести"); // вос-про-из-вес-ти
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("восстановите"); // вос-ста-но-ви-те
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[6], 1);
    EXPECT_EQ(result[8], 1);
    EXPECT_EQ(result[10], 1);
    result = hyphen->GetBreakCandidate("домну"); // домну
    EXPECT_EQ(result[3], 0);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest022
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest022, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("ru");
    auto result = hyphen->GetBreakCandidate("помни"); // помни
    EXPECT_EQ(result[2], 0);
    result = hyphen->GetBreakCandidate("умнем"); // умнем
    EXPECT_EQ(result[3], 0);
    result = hyphen->GetBreakCandidate("умнет"); // умнет
    EXPECT_EQ(result[3], 0);
    result = hyphen->GetBreakCandidate("грэс"); // грэс
    EXPECT_EQ(result[2], 0);
    result = hyphen->GetBreakCandidate("бездн"); // бездн
    EXPECT_EQ(result[2], 0);
    result = hyphen->GetBreakCandidate("аккаунт"); // акка-унт
    EXPECT_EQ(result[4], 1);
    result = hyphen->GetBreakCandidate("объектов"); // объ-ектов
    EXPECT_EQ(result[3], 1);
    result = hyphen->GetBreakCandidate("использовать"); // исполь-зовать
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("онлайнуслуг"); // онлайн-услуг
    EXPECT_EQ(result[6], 1);
    result = hyphen->GetBreakCandidate("онлайнконтента"); // онлайн-контента
    EXPECT_EQ(result[6], 1);
    delete hyphen;
}

/**
 * @tc.name: HyphenationTest023
 * @tc.desc: Test Hyphenation.GetBreakCandidate
 * @tc.type: FUNC
 */
HWTEST_F(HyphenationTest, HyphenationTest023, TestSize.Level1)
{
    Hyphenation* hyphen = Hyphenation::CreateInstance("nl");
    auto result = hyphen->GetBreakCandidate("vernederlandste"); // ver-ne-der-lands-te
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[5], 1);
    EXPECT_EQ(result[8], 1);
    EXPECT_EQ(result[13], 1);
    result = hyphen->GetBreakCandidate("waterstaatsingenieurs");
    EXPECT_EQ(result[5], 1); // wa-ter-staats-in-ge-ni-eurs
    result = hyphen->GetBreakCandidate("palingsteken"); // pa-ling-ste-ken
    EXPECT_EQ(result[2], 1);
    EXPECT_EQ(result[6], 1);
    EXPECT_EQ(result[9], 1);
    result = hyphen->GetBreakCandidate("kettingsteken"); // ket-ting-ste-ken
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[7], 1);
    EXPECT_EQ(result[10], 1);
    result = hyphen->GetBreakCandidate("donderaal"); // don-der-aal
    EXPECT_EQ(result[3], 1);
    EXPECT_EQ(result[6], 1);
    delete hyphen;
}
} // namespace I18N
} // namespace OHOS
/**
 * @file mifare-access-bits.h
 * @author Luciano Vieira Rodrigues (luciano.vieira@digicon.com.br)
 * @brief Calculadora de bits de acesso para setores de Cartões Mifare.
 * @version 1.0
 * @date 2021-12-13
 * 
 * @copyright Copyright (c) 2021
 */

#include <cstdint>
#include <iostream>

/**
 * @brief Tamanho, em bytes, da estrutura de condições de acesso 
 * de um setor de cartão Mifare.
 */
#define ACCESS_CONDITIONS_LENGTH    3

/**
 * @brief Calculadora de acesso para setores de Cartões Mifare.
 * 
 * @see https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf
 */
class MifareAccessBits {
    public:
        /**
         * @brief Estrutura com informações das condições de acesso
         * para um setor de Cartão Mifare.
         */
        typedef uint8_t AccessConditions[ACCESS_CONDITIONS_LENGTH];

        /**
         * @brief Condições de acesso para os blocos de dados.
         * 
         * As informações podem ser lidas como uma tabela, conforme a 
         * documentação da NXP, sendo:
         * 
         * <table>
         *  <tr>
         *      <td>Read</td>
         *      <td>Write</td>
         *      <td>Increment</td>
         *      <td>Decrement, Transfer, Restore</td>
         *  </tr>
         * </table>
         */
        typedef enum {
            KEYAB__KEYAB__KEYAB__KEYAB,     /**< Configuração inicial (C1 = 0, C2 = 0, C3 = 0).*/
            KEYAB__NEVER__NEVER__NEVER,     /**< Bloco de Leitura e Escrita (C1 = 0, C2 = 1, C3 = 0).*/
            KEYAB__KEYB___NEVER__NEVER,     /**< Bloco de Leitura e Escrita (C1 = 1, C2 = 0, C3 = 0).*/
            KEYAB__KEYB___KEYB___KEYAB,     /**< Bloco de valor (C1 = 1, C2 = 1, C3 = 0).*/
            KEYAB__NEVER__NEVER__KEYAB,     /**< Bloco de valor (C1 = 0, C2 = 0, C3 = 1).*/
            KEYB___KEYB___NEVER__NEVER,     /**< Bloco de Leitura e Escrita (C1 = 0, C2 = 1, C3 = 1).*/
            KEYB___NEVER__NEVER__NEVER,     /**< Bloco de Leitura e Escrita (C1 = 1, C2 = 0, C3 = 1).*/
            NEVER__NEVER__NEVER__NEVER      /**< Bloco de Leitura e Escrita (C1 = 1, C2 = 1, C3 = 1).*/
        } DataCondition;
    
        /**
         * @brief Condições de acesso para os blocos de finalização dos setores.
         * 
         * As informações podem ser lidas como uma tabela, conforma a
         * documentação na NXP, sendo:
         * 
         * <table>
         *  <tr>
         *      <td>Read Key A</td>
         *      <td>Write Key A</td>
         *      <td>Read Access Bits</td>
         *      <td>Write Access Bits</td>
         *      <td>Read Key B</td>
         *      <td>Write Key B</td>
         *  </tr>
         * </table>
         */
        typedef enum {
            NEVER__KEYA___KEYA___NEVER__KEYA___KEYA,        /**< (C1 = 0, C2 = 0, C3 = 0). */
            NEVER__NEVER__KEYA___NEVER__KEYA___NEVER,       /**< (C1 = 0, C2 = 1, C3 = 0). */
            NEVER__KEYB___KEYAB__NEVER__NEVER__KEYB,        /**< (C1 = 1, C2 = 0, C3 = 0). */
            NEVER__NEVER__KEYAB__NEVER__NEVER__NEVER,       /**< (C1 = 1, C2 = 1, C3 = 0). */
            NEVER__KEYA___KEYA___KEYA___KEYA___KEYA,        /**< (C1 = 0, C2 = 0, C3 = 1). */
            NEVER__KEYB___KEYAB__KEYB___NEVER__KEYB,        /**< (C1 = 0, C2 = 1, C3 = 1). */
            NEVER__NEVER__KEYAB__KEYB___NEVER__NEVER,       /**< (C1 = 1, C2 = 0, C3 = 1). */
            NEVER__NEVER__KEYAB__NEVER__NEVER__NEVEREX      /**< (C1 = 1, C2 = 1, C3 = 1). */
        } TraillerCondition;

        /**
         * @brief Construtor, utilizando os valores de fábrica para inicializar
         * as condições de acesso.
         */
        MifareAccessBits() {
            this->block0    = DataCondition::KEYAB__KEYAB__KEYAB__KEYAB;
            this->block1    = DataCondition::KEYAB__KEYAB__KEYAB__KEYAB;
            this->block2    = DataCondition::KEYAB__KEYAB__KEYAB__KEYAB;
            this->trailler  = TraillerCondition::NEVER__KEYA___KEYA___KEYA___KEYA___KEYA;
        }

        /**
         * @brief Configura as condições de acesso para o bloco 0 do setor.
         * 
         * @param condition DataCondition
         */
        void setBlock0(DataCondition condition) { this->block0 = condition; }

        /**
         * @brief Recupera as condições de acesso para o bloco 0 do setor.
         * 
         * @return DataCondition 
         */
        DataCondition getBlock0() { return this->block0; }

        /**
         * @brief Configura as condições de acesso para o bloco 1 do setor.
         * 
         * @param condition DataCondition
         */
        void setBlock1(DataCondition condition) { this->block1 = condition; }

        /**
         * @brief Recupera as condições de acesso para o bloco 1 do setor.
         * 
         * @return DataCondition 
         */
        DataCondition getBlock1() { return this->block1; }

        /**
         * @brief Configura as condições de acesso para o bloco 2 do setor.
         * 
         * @param condition DataCondition
         */
        void setBlock2(DataCondition condition) { this->block2 = condition; }

        /**
         * @brief Recupera as condições de acesso para o bloco 2 do setor.
         * 
         * @return DataCondition 
         */
        DataCondition getBlock2() { return this->block2; }

        /**
         * @brief Configura as condições de acesso para rodapé do setor, 
         * 
         * @param condition TraillerCondition
         */
        void setTrailler(TraillerCondition condition) { this->trailler = condition; }

        /**
         * @brief Recupra as condições de acesso para o rodapé do setor.
         * 
         * @return TraillerCondition 
         */
        TraillerCondition getTrailler() { return this->trailler; }

        /**
         * @brief Recupera o valor das condições de acesso configuradas para o setor.
         * 
         * @return AccessConditions& 
         */
        AccessConditions& value();

        /**
         * @brief Decodificador de enumerados.
         * 
         * @param os Fluxo de saída.
         * @param condition DataCondition
         * @return std::ostream& 
         */
        friend std::ostream& operator<<(std::ostream& os, const MifareAccessBits::DataCondition& condition);

        /**
         * @brief Decodificador de enumerados.
         * 
         * @param os Fluxo de saída.
         * @param condition TraillerCondition
         * @return std::ostream& 
         */
        friend std::ostream& operator<<(std::ostream& os, const MifareAccessBits::TraillerCondition& condition);
    private:
        /**
         * @brief Bits de condições de acesso para configuração dos
         * blocos e setores.
         */
        typedef struct {
            bool c1;        /**< BIT da condição 1. */
            bool c2;        /**< BIT da condição 2. */
            bool c3;        /**< BIT da condição 3. */
        } AccessBits;

        /**
         * @brief Condições de acesso para o bloco 0 do setor.
         */
        DataCondition block0;

        /**
         * @brief Condições de acesso para o bloco 1 do setor.
         */
        DataCondition block1;

        /**
         * @brief Condições de acesso para o bloco 2 do setor.
         */
        DataCondition block2;

        /**
         * @brief Condições de acesso para o rodapé do setor. 
         */
        TraillerCondition trailler;

        /**
         * @brief Recupera os bits de condição de acesso para os blocos de dados.
         * 
         * @param condition DataCondition
         * @return AccessBits 
         */
        AccessBits getDataCondition(DataCondition condition);

        /**
         * @brief Recupera os bits de condição de acesso para o rodapé do setor.
         * 
         * @param condition TraillerCondition
         * @return AccessBits 
         */
        AccessBits getTraillerCondition(TraillerCondition condition);
};
# Protocolo e resultados da Etapa 02

## Pergunta e métricas

Quanto a cobertura bloqueante e o volume de bloqueios mudam quando variamos a nota proxy, o limiar e a granularidade? Uma confirmação HTTP dirigida consegue suprir lacunas de evidência direta úteis para a P4?

Uma ocorrência é um registro de um scanner. Uma unidade de avaliação é o objeto que recebe uma decisão, inclusive um agregado quando previsto. A contagem de bloqueios soma unidades que disparariam a regra no seu estágio, sem interromper a avaliação nos estágios seguintes. Mede decisões simuladas sobre relatórios completos. A cobertura bloqueante é a quantidade de IDs de vulnerabilidade com pelo menos uma unidade bloqueada, dividida pelo número de IDs no escopo. A cobertura de detecção usa qualquer sinal. A cobertura direta usa pelo menos uma associação direta. As três métricas ficam separadas. Mede-se cobertura da referência delimitada. Precisão, recall global, tempos de triagem e redução de risco requerem validação adicional.

## Conjuntos e políticas originais

- Relatórios históricos da DVWA em nível baixo, artefato dos autores no commit `5b18244126350d1a6a4bf39e7a34701af9190563`. Foram processadas 1.750 ocorrências brutas, 1.575 de Trivy Container. O baseline tem 226 unidades, das quais 58 diretas, 48 indiretas e 120 sem matriz.
- A matriz contém 13 IDs no escopo. Outdated OS e Outdated Packages compartilham CWE-1104 e têm IDs e critérios estruturais distintos. A classe global é direta se houver pelo menos um vínculo direto. Se todos os vínculos forem indiretos, a classe global é indireta. A cobertura considera os vínculos da unidade bloqueada, com deduplicação pelo ID da vulnerabilidade.
- P1 é uniforme com limiar 9. P2 é uniforme com limiar 7. P3 usa limiar 7 e elegibilidade para diretas e sem matriz. Os limites são inclusivos. O script original trata ausência de score como zero para a decisão. São preservadas as regras específicas de associação dos autores.
- O baseline foi executado com a suíte dos autores e conferido com a referência publicada e com a evidência da Etapa 01 do grupo. Os CSVs foram derivados dos mesmos JSONs pelo novo script, usando os carregadores e a classificação auditados.

## Cenários

| Estudo | Condição | Linhas |
|---|---|---:|
| Proxy principal | Semgrep ERROR 5, 6, 7, 7,5, 8, 9 e 10. P1, P2, P3 nas regras originais | 21 |
| Proxy secundário | Semgrep WARNING 5, 6, 7, 8 e 9. ERROR em 7,5 e regras originais | 15 |
| Limiar | Uniforme e progressiva sob o mesmo limiar 5, 6, 7, 8 ou 9. ERROR em 7,5 | 10 |
| Grade | Nota ERROR × limiar comum × duas regras | 70 |
| Agregação original | Máximo, média e mediana em cada um dos três grupos, para P1, P2 e P3 | 9 |
| Trivy individual | As 1.575 ocorrências entram em Build individualmente e os três agregados saem | 3 |
| Leitura alternativa de ZAP Active | Nível textual convertido pelo mesmo mapa usado no Baseline | 3 |
| Aplicações-piloto | Regras originais e limiares comuns de 5 a 9 em cada recorte de três casos | 26 |

Proxy e limiar são variáveis independentes. Mudar a nota no pós-processamento pode mover achados através de um limiar, sem alterar o relatório ou a detecção do scanner. Os 51 achados ERROR estão no Commit. P2 e P3 só ganham esses 51 bloqueios quando a nota alcança 7. P1 os ganha quando alcança 9. Em P3, os casos com cobertura bloqueante passam de quatro para oito quando a nota cruza 7.

A perda de cobertura da progressiva em relação à uniforme é de 3, 4, 3, 2 e 1 vulnerabilidades, respectivamente entre os limiares 5 e 9 na DVWA. Os limiares 6 e 7 dão os mesmos 56 bloqueios e 8/13 na progressiva, enquanto a uniforme cai de 103 e 12/13 para 80 e 11/13. O grupo precisa definir a margem aceitável de perda antes de extrapolar a comparação. Os dados atuais sustentam uma análise descritiva.

## Verificações que afetam a interpretação

**IDs da diferença P2–P3.** Na base dos autores, com limiar 7, os três IDs cobertos só por P2 são CSRF, Weak Session IDs e Exposed MySQL. Open HTTP Redirect tem oito sinais indiretos, todos abaixo de 7, e permanece sem bloqueio em P2 e P3. A Seção 6.4 do artigo lista Open HTTP Redirect nessa diferença. A nova análise preserva o baseline numérico e apresenta a divergência por ID. Exposed MySQL tem sinais diretos abaixo do limiar e sinais indiretos que acionam P2.

**Agregação.** O grupo Outdated OS usa todas as 1.575 ocorrências quando há contexto EOSL. O grupo Outdated Packages usa as 1.380 com versão corrigida informada. O terceiro usa as 1.527 sem correspondência de CWE com a aplicação. Há sobreposição e as contagens de membros dos grupos têm finalidades próprias. Cada uma das três unidades conta uma vez por política. Valores ausentes são excluídos das estatísticas. Os máximos são todos 9,8. As médias ficam pouco abaixo de 7. Ao usar média, P3 passa de 56 para 53 e de 8/13 para 6/13. Com mediana, P3 permanece no baseline e P1 perde as duas coberturas estruturais. O cálculo usa a precisão completa da média.

**Todas as ocorrências individuais.** Esse cenário muda a unidade de contagem, chegando a 1.750 unidades. A cobertura estrutural dos dois agregados antigos deixa de ser representada. A associação das ocorrências do container fica restrita a CWEs APP. Os bloqueios são 272, 891 e 867 para P1, P2 e P3. As coberturas bloqueantes da matriz original são 1/13, 9/13 e 6/13, com dois casos estruturais indisponíveis nesse cenário. A contagem de bloqueios e o denominador de unidades precisam ser lidos em conjunto.

**Leitura do ZAP ativo na DVWA.** O JSON histórico traz categorias de risco em texto. O código original tenta converter `risk` em inteiro e as 14 unidades ativas ficam sem score. A variação diagnóstica converte High, Medium, Low e Informational para 7,5, 5,0, 3,0 e 0,0. P2 e P3 ganham um bloqueio no Deploy, sem alteração na cobertura bloqueante de nenhuma das três políticas. A versão histórica e a variação ficam em saídas distintas.

## Política P4 proposta

1. Rodar a P3 com limiar 7 sobre as unidades originais.
2. Um ID com sinal indireto, zero evidência direta e sem cobertura bloqueante vira candidato a um teste dirigido, com uma validação por ID e configuração. Na DVWA, os candidatos são CSRF, Weak Session IDs e Open HTTP Redirect.
3. Guardar o estado `confirmada`, `nao_confirmada`, `inconclusiva` ou `nao_executada`, com configuração, referência e hash da evidência quando houver teste. Uma execução inconclusiva permanece visível para triagem.
4. **P4-A recomendada para avaliação.** Somar uma decisão de bloqueio no Deploy por confirmação nova, vinculada ao ID da matriz. **P4-B exploratória.** Pedir também score de confirmação igual ou superior a 7. A nota precisa ser avaliada para o caso confirmado. O score da CVE de origem é insuficiente para esse fim.
5. Em implantação real, definir o catálogo de testes por versão, tempo limite, responsáveis e comportamento diante de indisponibilidade. O simulador modela decisões de portão. A integração com um pipeline operacional é uma tarefa posterior.

Na DVWA, a P4-A pode adicionar de zero a três decisões às 56 da P3. O resultado máximo condicional é 59 bloqueios e 11/13, com conjunto de IDs diferente do de P2. Esse máximo depende de três confirmações. Veja `results/p4_resultados.csv` para o cenário avaliado no laboratório e `results/p4_cenarios_condicionais.csv` para a análise hipotética.

## Outras aplicações

O recorte em Juice Shop e WebGoat foi definido com casos localizáveis no código de cada release. A matriz exploratória tem três entradas por alvo. A classificação de SAST exige o arquivo do caso e o CWE correspondente. O ZAP ativo exige endpoint e CWE. Uma ocorrência do Trivy de imagem com CWE coincidente produz vínculo indireto. As demais ocorrências de Trivy são condensadas em uma unidade sem matriz, com CVSS máximo. Para cada caso, classifica-se o vínculo por estágio, com a mesma precedência global. A simulação conta Semgrep, Trivy Image e ZAP ativo. Checkov Dockerfile, Trivy FS e ZAP passivo testam viabilidade operacional. A íntegra do pipeline histórico requer infraestrutura comparável e uma matriz independente e mais abrangente.

Em limiar 7, no recorte do Juice Shop, a progressiva reduz 10 para 8 bloqueios e 2/3 para 1/3 de cobertura bloqueante. No WebGoat, as duas regras ficam em 15 bloqueios e 1/3. Os pilotos usam conjuntos de regras adaptados à linguagem, versões fixadas e um ZAP ativo de duas regras sobre uma rota por aplicação, sem login. As diferenças mostram sensibilidade ao contexto do piloto. A magnitude entre aplicações depende do escopo, da imagem e do número de regras e rotas.

## Decisões para o grupo

- Ratificar P4-A e o limiar de severidade independente se P4-B continuar no estudo.
- Fixar o orçamento de cobertura aceitável antes de interpretar uma comparação confirmatória. Adotar um denominador auditado e justificar a margem em número de casos e pontos percentuais.
- Definir cenários equivalentes entre aplicações, ampliar o conjunto versionado de casos e confirmar cada vínculo relevante diretamente no artefato ou no laboratório.
- Divisão sugerida. Uma pessoa amplia a matriz e revisa associações. Outra configura autenticação e padroniza a coleta. A terceira integra políticas e análise. Revisão cruzada do artigo e dos slides.

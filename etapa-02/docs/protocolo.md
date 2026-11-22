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

## Sensibilidade de todas as notas proxy

O script `scripts/sensibilidade_proxies.py` lê apenas `data/normalized/dvwa.json` e varia todos os mapeamentos arbitrários do script original, não só o Semgrep. Cada grupo muda inteiro, como mudaria o mapa de severidade.

| Grupo | Unidades | Nota base | Origem da nota |
|---|---:|---:|---|
| Semgrep ERROR | 51 | 7,5 | Rótulo do scanner, mapa fixo |
| Semgrep WARNING | 26 | 5,0 | Rótulo do scanner, mapa fixo |
| Checkov | 63 | 5,0 | **Nenhuma.** O JSON bruto traz `severity: null` nas 63 reprovações e o código aplica `MEDIUM` por padrão |
| ZAP Baseline Medium | 5 | 5,0 | `riskcode` 2, mapa fixo |
| ZAP Baseline Low | 7 | 3,0 | `riskcode` 1, mapa fixo |
| Brute Force e Default Credentials | 2 | 7,5 | Valor fixo no código do teste customizado |

Saídas. `sensibilidade_proxies_individuais.csv` (cada grupo de 3 a 10, P1–P3), `sensibilidade_tornado.csv` (cada grupo em base − 2 e base + 2, os demais fixos), `sensibilidade_monte_carlo_resumo.csv` e `sensibilidade_monte_carlo_distribuicao.csv` (10.000 sorteios independentes por cenário, semente 20261122). Gráficos `figures/dvwa_tornado_proxies` e `figures/dvwa_monte_carlo_reducao`.

**Resultados.**

- Checkov é a maior nota arbitrária em volume. Em 7, P2 vai de 80 para 143 bloqueios e P3 de 56 para 119, com a cobertura de P3 passando de 8 para 9/13 (Exposed MySQL). A redução de P3 frente a P2 cai para 24/143 = 17%.
- Com o teste de credenciais abaixo de 7, P3 perde Brute Force e Default Credentials e fica em 6/13.
- A redução de 30% do artigo é um ponto de uma faixa. Variando uma nota por vez em ± 2, ela vai de 17% (Checkov em 7) a 83% (Semgrep ERROR em 5,5).
- Na variação conjunta com todas as notas em base ± 2, 62% das amostras ficam em 30–31% e 38% em 83–89%. Só os dois grupos de base 7,5 (Semgrep ERROR e teste de credenciais) cruzam o corte 7 com probabilidade positiva. O pico de 89% (P2 27, P3 3) ocorre quando ambos ficam abaixo de 7. Os grupos de base 5 só alcançam 7 no extremo da faixa; cerca de 0,2% dos sorteios caíram exatamente em 7,00 após o arredondamento e produzem os valores isolados de 17% a 29%, que são artefato de borda.
- Com todas as notas entre 1 e 10, a redução vai de 13% a 89%, com mediana 30%, e só 24% das amostras ficam entre 25% e 35%.
- A distribuição é bimodal porque os 51 alertas ERROR cruzam o corte 7 juntos.
- O resultado qualitativo resiste. Em todas as 20.000 amostras, P3 bloqueia menos que P2 e perde de 2 a 5 casos de cobertura bloqueante. O que não resiste é a magnitude.

A amplitude ± 2 e a faixa 1–10 são escolhas do grupo. Os sorteios são independentes entre grupos e não impõem ERROR ≥ WARNING.

## Política P4 proposta

1. Rodar a P2 e a P3 com limiar 7 sobre as unidades originais.
2. Entra na fila de teste dirigido todo ID sem bloqueio em P3 que atenda a um dos critérios. **apenas_indireta**: só há sinais indiretos (critério da primeira versão). **perda_p2_p3**: o ID é bloqueado em P2 e deixa de ser em P3, mesmo havendo sinal direto abaixo do limiar. Na DVWA, a fila tem CSRF, Weak Session IDs e Open HTTP Redirect pelo primeiro critério e Exposed MySQL pelo segundo. Com isso, toda perda de cobertura de P2 para P3 passa pela fila.
3. Guardar o estado `confirmada`, `nao_confirmada`, `inconclusiva` ou `nao_executada`, com configuração, referência e hash da evidência quando houver teste. Uma execução inconclusiva permanece visível para triagem.
4. **P4-A.** Somar uma decisão de bloqueio no Deploy por confirmação nova, vinculada ao ID da matriz. **P4-B.** Exigir também nota CVSS v3.1 do caso confirmado igual ou superior a 7. A nota sai do vetor registrado em `validacoes.csv` (`scripts/cvss31.py`), não da CVE de origem. **P4-B-alt** repete a P4-B com um vetor alternativo, para medir a dependência da escolha do vetor.
5. Em implantação real, definir o catálogo de testes por versão, tempo limite, responsáveis e comportamento diante de indisponibilidade. O simulador modela decisões de portão. A integração com um pipeline operacional é uma tarefa posterior.

**Vetores propostos (a ratificar pelo grupo).**

| Caso | Vetor principal | Nota | Vetor alternativo | Nota |
|---|---|---:|---|---:|
| CSRF | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`. A troca forjada define uma senha conhecida pelo atacante, o que leva à tomada da conta | 8,1 | `C:N/I:H/A:N`. Conta só a alteração demonstrada | 6,5 |
| Weak Session IDs | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`. A evidência se limita ao cookie de treino `dvwaSession`, que não autentica | 5,3 | `C:H/I:H/A:N`. Trata o cookie como identificador de sessão real | 9,1 |

**Resultados na DVWA.** P3 56 e 8/13. P4-A 58 e 10/13 (CSRF e Weak Session IDs). P4-B 57 e 9/13 (CSRF). P4-B-alt 57 e 9/13 (Weak Session IDs). Com os dois vetores, P4-B acrescenta um caso, mas um caso diferente em cada vetor, então a escolha do vetor decide qual lacuna é fechada. P2 tem 80 e 11/13 como referência. O máximo condicional da P4-A, com as quatro lacunas confirmadas, é 60 bloqueios e 12/13, acima da cobertura de P2 com 20 bloqueios a menos (`results/p4_cenarios_condicionais.csv`).

**Pendências da fila.**

- **Exposed MySQL (`nao_executada`).** Os 11 sinais "diretos" do artigo vêm do Checkov: `CKV_K8S_29/30/31/38` (contexto de segurança e token de service account nos Deployments `mysql` e `dvwa-app`), `CKV_GCP_21` (labels do cluster) e `CKV_GCP_62` (log de acesso a buckets). Nenhuma dessas verificações testa a exposição do MySQL, o que enfraquece a classificação direta desse caso. O teste comportamental é tentar conexão TCP e autenticação na porta 3306 de fora da fronteira da aplicação. Ele exige reproduzir o Service do manifesto `k8s/mysql.yaml` dos autores, que não foi publicado no artefato. Um `docker run` local que publica só a porta 80 daria `nao_confirmada` por construção, sem informação sobre o ambiente do artigo.
- **Open HTTP Redirect (`inconclusiva`).** O relatório Semgrep dos autores contém caminhos `vulnerabilities/open_redirect`, `api`, `bac` e `cryptography`, módulos do código atual da DVWA. Na imagem histórica testada, as duas rotas de redirecionamento sondadas responderam HTTP 404 (as demais não foram sondadas). Isso indica que o SAST do artigo pode ter analisado uma versão do código diferente da imagem implantada. Para fechar o caso, listar a árvore da imagem fixada: `docker run --rm --entrypoint ls vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7 /var/www/html/vulnerabilities`. Se o módulo não existir, registrar `nao_confirmada` com esse laudo.

## Outras aplicações

O recorte em Juice Shop e WebGoat foi definido com casos localizáveis no código de cada release. A matriz exploratória tem três entradas por alvo. A classificação de SAST exige o arquivo do caso e o CWE correspondente. O ZAP ativo exige endpoint e CWE. Uma ocorrência do Trivy de imagem com CWE coincidente produz vínculo indireto. As demais ocorrências de Trivy são condensadas em uma unidade sem matriz, com CVSS máximo. Para cada caso, classifica-se o vínculo por estágio, com a mesma precedência global. A simulação conta Semgrep, Trivy Image e ZAP ativo. Checkov Dockerfile, Trivy FS e ZAP passivo testam viabilidade operacional. A íntegra do pipeline histórico requer infraestrutura comparável e uma matriz independente e mais abrangente.

Em limiar 7, no recorte do Juice Shop, a progressiva reduz 10 para 8 bloqueios e 2/3 para 1/3 de cobertura bloqueante. No WebGoat, as duas regras ficam em 15 bloqueios e 1/3. Os pilotos usam conjuntos de regras adaptados à linguagem, versões fixadas e um ZAP ativo de duas regras sobre uma rota por aplicação, sem login. As diferenças mostram sensibilidade ao contexto do piloto. A magnitude entre aplicações depende do escopo, da imagem e do número de regras e rotas.

## Decisões para o grupo

- Ratificar P4-A e os vetores CVSS de CSRF e Weak Session IDs usados por P4-B e P4-B-alt.
- Rodar a listagem da imagem para o Open HTTP Redirect e decidir se o Exposed MySQL será testado em um cluster que reproduza o manifesto dos autores.
- Fixar o orçamento de cobertura aceitável antes de interpretar uma comparação confirmatória. Adotar um denominador auditado e justificar a margem em número de casos e pontos percentuais.
- Definir cenários equivalentes entre aplicações, ampliar o conjunto versionado de casos e confirmar cada vínculo relevante diretamente no artefato ou no laboratório.
- Divisão sugerida. Uma pessoa amplia a matriz e revisa associações. Outra configura autenticação e padroniza a coleta. A terceira integra políticas e análise. Revisão cruzada do artigo e dos slides.

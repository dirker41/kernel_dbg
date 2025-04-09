#ifndef __PROD_ETH_CARD_DBG_H
#define __PROD_ETH_CARD_DBG_H

typedef enum {
	HAL_ENU_ETH_CARD_CMD_TYPE_HELLO=0,
	HAL_ENU_ETH_CARD_CMD_TYPE_DBG_MSG_SETUP,
	HAL_ENU_ETH_CARD_CMD_TYPE_CFG_RELOAD,
	HAL_ENU_ETH_CARD_CMD_TYPE_DBG_CORT_SETUP,
	HAL_ENU_ETH_CARD_CMD_TYPE_DBG_CORT_RX_SETUP,
	HAL_ENU_ETH_CARD_CMD_TYPE_SET_XC,
	HAL_ENU_ETH_CARD_CMD_TYPE_SHOW_PORT_MAP,
	HAL_ENU_ETH_CARD_CMD_TYPE_TE1_32_CPU_LIMIT,
	HAL_ENU_ETH_CARD_CMD_TYPE_LS_PDH_SLOT_EN_IMPLEMENT,
	HAL_ENU_ETH_CARD_CMD_TYPE_DBG_LS_CORT_SETUP,
	HAL_ENU_ETH_CARD_CMD_TYPE_DBG_LS_CORT_RX_SETUP,
	HAL_ENU_ETH_CARD_CMD_TYPE_DBG_REPLACE_TE1_TO_TE1_FR,
	HAL_ENU_ETH_CARD_CMD_TYPE_TOTAL,
}HAL_ENU_ETH_CARD_CMD_TYPE;

typedef enum {
	HAL_ENU_DS3_COMM_DBG_MSG_TYPE_DBG,
	HAL_ENU_DS3_COMM_DBG_MSG_TYPE_MPLS_DBG,
}HAL_ENU_ETH_CARD_DBG_MSG_TYPE;

typedef int(*HandlerPtr)(int, char*);

void ethCardDbgInitial(void);
void ethCardDbgLoadDefaultCfg(void);

void ethCardDbgRegCmdHandle(HAL_ENU_ETH_CARD_CMD_TYPE cmd, char *cmp_str, char *arg, char *helper, HandlerPtr handler, int setup);
int ethCardDbgSendPkt(int gport, int len, void *data);
int ethCardDbgSendPwAcrLogPkt(int gport, u16 pw_id, u16 state);
int ethCardDbgGetInt(char *str, char **end);
u32 ethCardDbgGetValue(char *str, char **end);
char* ethCardDbgGetToken(char *str, char **end);

//int ethCardDbgSkbRxRegister(int port, int eth_type, ethCardDbgSkbRxHandle skb_rx_handle);
int ethCardDbgSkbRxUnregister(int port, int eth_type);
int ethCardDbgHandleSkbRx(int port, struct sk_buff  *skb);
int ethCardDbgHandleSkbRxForce(int port, struct sk_buff  *skb);

int handler_save_cfg(int handler_index, char *arg);

void ethCardDbgSetAcl(int entry_id);
int ethCardDbgAutonegAlwaysDisable(void);
int ethCardDbgSetupGet(HAL_ENU_ETH_CARD_CMD_TYPE type);
void ethCardDbgSetupSet(HAL_ENU_ETH_CARD_CMD_TYPE type, int val);

int ethCardDbgSlotAsDs3Get(int slot);

int ethCardDbgCortMatch(int type);
int ethCardDbgCortRxMatch(int type);
int ethCardDbgLsCortMatch(int type);
int ethCardDbgLsCortRxMatch(int type);
int ethCardDbgMemDump(char *prefix, const void *addr, int len);


int ethCardDbg_skb_rx_handle_proc_show(struct seq_file *m);

#endif /* __PROD_ETH_CARD_DBG_H */

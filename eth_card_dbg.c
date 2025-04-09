/********************************** Include *********************************/
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/semaphore.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kthread.h>
#include <linux/skbuff.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/kernel.h> 

static int s_debug_cfg_exist=0;
#define BRYANT_DEBUG(fmt, args...) \
	if(s_debug_cfg_exist) {                        \
		printk(KERN_EMERG "\r\n%s %s "fmt, "eth_card_dbg.c", __FUNCTION__, ##args); \
		printk(KERN_EMERG "\r\n"); \
	}

/********************************* Definitions ******************************/
typedef struct{
	HAL_ENU_ETH_CARD_CMD_TYPE type;
	char map_str[50];
	char arg[256];
	char helper[512];
	HandlerPtr handler;
	int setup;
	void *ptr;
}ETH_CARD_HANDLE;


//static u32 s_pw_ts_cnt[4][128];

static int s_handler_len=0;
static ETH_CARD_HANDLE s_handle_arr[100];

static int eth_proc_open(struct inode *inode, struct file *filp);
static int eth_proc_show(struct seq_file *m, void *v);
static ssize_t eth_proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos);

static const struct proc_ops eth_proc_ops={
	.proc_open		= eth_proc_open,
	.proc_read		= seq_read,
	.proc_lseek		= seq_lseek,
	.proc_release	= single_release,
	.proc_write		= eth_proc_write,
};

static int 
ch_is_num(char ch){
	if (ch>='0' && ch<='9')
		return 1;

	return 0;
}

static int 
ch_is_lower_case(char ch){
	if (ch>='a' && ch<='z')
		return 1;

	return 0;
}

static int 
ch_is_upper_case(char ch){
	if (ch>='A' && ch<='Z')
		return 1;

	return 0;
}


static int 
str2dec(char* str)
{
	int base=0;
	char *ch=str;

	while(ch_is_num(*ch))
	{

		base=base*10+*ch-'0';

		ch++;
	}

	return base;
}

static int 
str2hex(char* str)
{
	int base=0;
	char *ch=str;
	const int shift=4;

	while( ch_is_num(*ch) || 
			ch_is_lower_case(*ch) || 
			ch_is_upper_case(*ch)  )
	{
		if(ch_is_num(*ch))
			base=(base<<shift)+*ch-'0';
		else if(ch_is_lower_case(*ch))
			base=(base<<shift)+*ch-'a'+10;
		else if(ch_is_upper_case(*ch))
			base=(base<<shift)+*ch-'A'+10;

		ch++;
	}

	return base;
}

static int 
str2value(char* str)
{
	if(strncmp(str, "0x", 2)==0)
		return str2hex(str+2);
	else 
		return str2dec(str);
}

static int 
ch2hex(char ch)
{
	if(ch_is_num(ch))
		return ch-'0';
	else if(ch_is_lower_case(ch))
		return ch-'a'+10;
	else if(ch_is_upper_case(ch))
		return ch-'A'+10;
	else 
		return 0;
}

char *
ethCardDbgGetToken(char *str, char **end)
{
	char *ch=str;
	char *token;

	if(*ch==0x00)
		return ch;

	while(*ch!=0x00 && isspace(*ch))
	{
		ch++;
	}

	token=ch;

	while(*ch!=0x00 && !isspace(*ch))
	{
		ch++;
	}

	*ch=0x00;
	ch++;
	*end=ch;

	return token;
}

int 
ethCardDbgGetInt(char *str, char **end)
{
	char *token=NULL;

	token=ethCardDbgGetToken(str, end);

	return str2dec(token);
}

u32 
ethCardDbgGetValue(char *str, char **end)
{
	char *token=NULL;

	token=ethCardDbgGetToken(str, end);

	if(strncmp(token, "0x", 2)==0)
		return str2hex(token+2);
	else 
		return str2dec(token);
}

int  
ethCardDbgGetMac(char *str, char **end, char* mac)
{
	char *token=NULL;
	int i;

	token=ethCardDbgGetToken(str, end);


	for(i=0;i<6;i++)
	{
		mac[i]=str2hex(&token[3*i]);
	}

	return 0;
}

static ETH_CARD_HANDLE* 
get_handle(HAL_ENU_ETH_CARD_CMD_TYPE type)
{
	int i=0;
	for(i=0; i < s_handler_len ; i++)
	{
		if(s_handle_arr[i].type==type)
			return &s_handle_arr[i];
	}
	return NULL;
}

int 
handler_save_cfg(int handler_index, char *arg)
{
	char *end;
	char *setup_str;
	ETH_CARD_HANDLE* handle=&s_handle_arr[handler_index];

	if(!handle)
		return 0;

	setup_str=ethCardDbgGetToken(arg, &end);

	if(strlen(setup_str)==0)
	{
		if(handle->setup)
			handle->setup=0;
		else 
			handle->setup=1;

		return 0;
	}

	if(strcmp(setup_str, "disable")==0)
	{
		handle->setup=0;
	}
	else if(strcmp(setup_str, "enable")==0)
	{
		handle->setup=1;
	}
	else {
		handle->setup=str2value(setup_str);
	}
	
	return 0;
}

int 
handle_cfg_reload(int handler_index, char *arg)
{
	ethCardDbgLoadDefaultCfg();
	return 0;
}

int 
ethCardDbgMemDump(char *prefix, const void *addr, int len)
{
	printk(KERN_EMERG "\r\n%s\r\n", prefix);
	//dbgKernMemDump(addr, 0, len);

	return 0;
}

static int 
common_dbg_handle(int handler_index, char *arg)
{
	char *end;
	int setup;
	char *token=NULL;
	int num;
	u8 *list;
	
	ETH_CARD_HANDLE* handle=&s_handle_arr[handler_index];

	if(!handle)
		return 0;

	setup=ethCardDbgGetInt(arg, &end);

	if(setup)
		handle->setup=1;
	else 
		handle->setup=0;

	token=ethCardDbgGetToken(end, &end);

	list = handle->ptr;
	if(strncmp(token, "all", 3)==0)
	{
		int i;
		for(i=0;i<256;i++)
		{
			list[i]=setup;
		}
	}
	else 
	{
		if(strncmp(token, "0x", 2)==0)
			num=str2hex(token+2);
		else 
			num=str2dec(token);

		if(num<256)
			list[num]=setup;
	}

	while((num=ethCardDbgGetValue(end, &end))>0)
	{
		if(num<256)
			list[num]=setup;
	}

	return 0;
}

static int 
common_dbg_match(int cmd, int type)
{
	static ETH_CARD_HANDLE* handle;
	u8 *list;

	handle=get_handle(cmd);
	
	if(type>=256)
		return 0;

	if(!handle)
		return 0;

	list = handle->ptr;

	return list[type];
}

int 
handle_dbg_cort(int handler_index, char *arg)
{
	return common_dbg_handle(handler_index, arg);
}

int 
ethCardDbgCortMatch(int type)
{
	return common_dbg_match(HAL_ENU_ETH_CARD_CMD_TYPE_DBG_CORT_SETUP, type);
}

int 
handle_dbg_cort_rx(int handler_index, char *arg)
{
	return common_dbg_handle(handler_index, arg);
}

int 
ethCardDbgCortRxMatch(int type)
{
	return common_dbg_match(HAL_ENU_ETH_CARD_CMD_TYPE_DBG_CORT_RX_SETUP, type);
}

int 
handle_dbg_ls_cort(int handler_index, char *arg)
{
	return common_dbg_handle(handler_index, arg);
}

int 
ethCardDbgLsCortMatch(int type)
{
	return common_dbg_match(HAL_ENU_ETH_CARD_CMD_TYPE_DBG_LS_CORT_SETUP, type);
}

int 
handle_dbg_ls_cort_rx(int handler_index, char *arg)
{
	return common_dbg_handle(handler_index, arg);
}

int 
ethCardDbgLsCortRxMatch(int type)
{
	return common_dbg_match(HAL_ENU_ETH_CARD_CMD_TYPE_DBG_LS_CORT_RX_SETUP, type);
}

static int 
my_ctc_scl_add_entry(uint32 group_id, ctc_scl_entry_t* scl_entry)
{
	int ret=0;

	ret=ctc_scl_add_entry(group_id, scl_entry);
	if(ret==CTC_E_HASH_CONFLICT)
	{
		//BRYANT_DEBUG("%s err", ctc_get_error_desc(ret));
		scl_entry->resolve_conflict=1;
		ret=ctc_scl_add_entry(group_id, scl_entry);
	}

	return ret;
}

//=============HAL_ENU_ETH_CARD_CMD_TYPE_SET_XC=================

static int
set_swport_redirect(int src_gport, int dst_gport)
{
	int entry_id;
	ctc_scl_entry_t scl_entry;
	int ret=0;
	ctc_port_scl_property_t property;
	
	memset(&property, 0, sizeof(property));
	memset(&scl_entry, 0, sizeof(scl_entry));
	
	property.direction=CTC_INGRESS;
	property.scl_id=SCL_ID_NON_MPLS;
	property.tcam_type=CTC_PORT_IGS_SCL_TCAM_TYPE_DISABLE;
	property.hash_type=CTC_PORT_IGS_SCL_HASH_TYPE_PORT;
	ctc_port_set_scl_property(src_gport, &property);

	entry_id=SwitchSclAllocEntryId();

	if(entry_id<0)
	{
		return -1;
	}

	scl_entry.entry_id=entry_id;
	scl_entry.key.type=CTC_SCL_KEY_HASH_PORT;
	if(ctc_nh_get_l2uc(dst_gport, CTC_NH_PARAM_BRGUC_SUB_TYPE_BASIC, &scl_entry.action.u.igs_action.nh_id)!=CTC_E_NONE)
	{
		return(-1);
	}

	scl_entry.key.u.hash_port_key.gport=src_gport;
	scl_entry.key.u.hash_port_key.gport_type=CTC_SCL_GPROT_TYPE_PORT;
	scl_entry.key.u.hash_port_key.dir=CTC_INGRESS;
	scl_entry.action.type=CTC_SCL_ACTION_INGRESS;
	scl_entry.action.u.igs_action.flag|=CTC_SCL_IGS_ACTION_FLAG_REDIRECT;

	if((ret=ctc_scl_add_entry(CTC_SCL_GROUP_ID_HASH_PORT, &scl_entry))!=CTC_E_NONE)
	{
		return(-1);
	}

	if((ret=ctc_scl_install_entry(entry_id))!=CTC_E_NONE)
	{
		return(-1);
	}

	return 0;
}

static int 
handler_set_xc(int handler_index, char *arg) 
{
	char *end;
	int src_gport = ethCardDbgGetInt(arg, &end);
	int dst_gport = ethCardDbgGetInt(end, &end);

	if(set_swport_redirect(src_gport, dst_gport)<0)
	{
		return -1;
	}

	if(set_swport_redirect(dst_gport, src_gport)<0)
	{
		return -1;
	}

	return 0;
}

static int 
handler_show_port_map(int handler_index, char *arg) 
{
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "|port|        More Description         |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "|  0 | LS eIPC and CES                 |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "|  2 | Backplane 1G from/to S9         |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "|  3 | Backplane 1G from/to S10        |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "|  4 | Backplane 1G from/to S5         |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "|  5 | Backplane 1G from/to S6         |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "|  6 | Backplane 1G from/to S7         |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "|  7 | Backplane 1G from/to S8         |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "| 14 | Backplane 10G from/to S6        |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "| 15 | Backplane 10G from/to S5        |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "| 16 | Backplane 1G from/to S1         |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "| 17 | Backplane 1G from/to S2         |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "| 18 | Backplane 1G from/to S3         |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "| 19 | Backplane 1G from/to S4         |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "| 24 | Backplane 10G from/to S?        |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "| 28 | Backplane 10G from/to S4        |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "| 29 | Backplane 10G from/to S3        |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "| 30 | VER.B: Front panel 10G          |\r\n");
	printk(KERN_EMERG "|    | VER.C: Backplane 10G from/to S? |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	printk(KERN_EMERG "| 59 | VER.B: Front panel 10G          |\r\n");
	printk(KERN_EMERG "|    | VER.C: Backplane 10G from/to S? |\r\n");
	printk(KERN_EMERG "+----+---------------------------------+\r\n");
	return 0;
}

void
ethCardDbgRegCmdHandleWithPtr(HAL_ENU_ETH_CARD_CMD_TYPE cmd, char *cmp_str, char *arg, char *helper, 
                              HandlerPtr handler, int setup, void *ptr)
{
	s_handle_arr[s_handler_len].type=cmd;
	snprintf(s_handle_arr[s_handler_len].map_str, sizeof(s_handle_arr[s_handler_len].map_str), "%s", cmp_str);
	snprintf(s_handle_arr[s_handler_len].arg, sizeof(s_handle_arr[s_handler_len].arg), "%s", arg);
	snprintf(s_handle_arr[s_handler_len].helper, sizeof(s_handle_arr[s_handler_len].helper), "%s", helper);
	s_handle_arr[s_handler_len].handler=handler;
	s_handle_arr[s_handler_len].setup=setup;
	s_handle_arr[s_handler_len].ptr=ptr;

	s_handler_len++;
}

void
ethCardDbgRegCmdHandle(HAL_ENU_ETH_CARD_CMD_TYPE cmd, char *cmp_str, char *arg, char *helper, 
                       HandlerPtr handler, int setup)
{
	ethCardDbgRegCmdHandleWithPtr(cmd, cmp_str, arg, helper, handler, setup, NULL);
	
}

static void *
malloc_0(int size)
{
	void *ptr;

	ptr=kmalloc(size, GFP_KERNEL);
	memset(ptr, 0x00, size);

	return ptr;
}

static void 
handle_init(void)
{
	void *ptr;

	ethCardDbgRegCmdHandle(HAL_ENU_ETH_CARD_CMD_TYPE_DBG_MSG_SETUP, "eth_card_dbg_msg_setup", 
	"[bit_map]", "eth_card debug message setup", handler_save_cfg, 0);

	ethCardDbgRegCmdHandle(HAL_ENU_ETH_CARD_CMD_TYPE_CFG_RELOAD, "reload", 
	"", "reload config file", handle_cfg_reload, 0);


	ptr=malloc_0(sizeof(u8)*256);
	ethCardDbgRegCmdHandleWithPtr(HAL_ENU_ETH_CARD_CMD_TYPE_DBG_CORT_SETUP, "eth_card_dbg_cort_setup", 
	"[int] type[ type]", "CORT debug message setup, 0=dis, 1=en", handle_dbg_cort, 0, ptr);

	ptr=malloc_0(sizeof(u8)*256);
	ethCardDbgRegCmdHandleWithPtr(HAL_ENU_ETH_CARD_CMD_TYPE_DBG_CORT_RX_SETUP, "eth_card_dbg_cort_rx_setup", 
	"[int] type[ type]", "CORT debug rx message setup, 0=dis, 1=en, ", handle_dbg_cort_rx, 0, ptr);

	ethCardDbgRegCmdHandle(HAL_ENU_ETH_CARD_CMD_TYPE_SET_XC, "set_xc", 
	"[src_switch_port] [dst_switch_port]", "set xconnect at 2 switch port.", handler_set_xc, 0);

	ethCardDbgRegCmdHandle(HAL_ENU_ETH_CARD_CMD_TYPE_SHOW_PORT_MAP, "show_port_map", 
	"", "show gport and slot mapping.", handler_show_port_map, 0);

	ethCardDbgRegCmdHandle(HAL_ENU_ETH_CARD_CMD_TYPE_TE1_32_CPU_LIMIT, "te1_32_cpu_limit", 
	"[max cpu]", "set max cpu for TE1-32 card.", handler_save_cfg, 0);

	ethCardDbgRegCmdHandle(HAL_ENU_ETH_CARD_CMD_TYPE_LS_PDH_SLOT_EN_IMPLEMENT, "ls_pdh_slot_en_imlement", 
	"[setup]", "send LS_CMD_TYPE_PDH_SLOT_ENABLE to PDH.", handler_save_cfg, 0);

	ptr=malloc_0(sizeof(u8)*256);
	ethCardDbgRegCmdHandleWithPtr(HAL_ENU_ETH_CARD_CMD_TYPE_DBG_LS_CORT_SETUP, "eth_card_dbg_ls_cort_setup", 
	"[int] type[ type]", "LS CORT debug message setup, 0=dis, 1=en", handle_dbg_ls_cort, 0, ptr);

	ptr=malloc_0(sizeof(u8)*256);
	ethCardDbgRegCmdHandleWithPtr(HAL_ENU_ETH_CARD_CMD_TYPE_DBG_LS_CORT_RX_SETUP, "eth_card_dbg_ls_cort_rx_setup", 
	"[int] type[ type]", "LS CORT debug rx message setup, 0=dis, 1=en, ", handle_dbg_ls_cort_rx, 0, ptr);

	ethCardDbgRegCmdHandle(HAL_ENU_ETH_CARD_CMD_TYPE_DBG_REPLACE_TE1_TO_TE1_FR, "replace_te1_to_te1_fr", 
	"[setup]", "replace te1 heartbeat to te1-fr", handler_save_cfg, 0);

	ethCardDbgLoadDefaultCfg();
}

int 
ethCardDbgSetupGet(HAL_ENU_ETH_CARD_CMD_TYPE type)
{
	ETH_CARD_HANDLE *handle=get_handle(type);

	if(!handle)
		return 0;

	return handle->setup;
}

void 
ethCardDbgSetupSet(HAL_ENU_ETH_CARD_CMD_TYPE type, int val)
{
	ETH_CARD_HANDLE *handle=get_handle(type);

	if(!handle)
		return ;

	handle->setup=val;
}

void
ethCardDbgInitial(void)
{
	struct proc_dir_entry *entry;
	struct proc_dir_entry *proc_dir=proc_mkdir("board/ethCard", NULL);

	if(!proc_dir)
	{
		printk(KERN_ERR "Failed to create ethCard control file (summary)!\n");
		return ;
	}

	entry=proc_create("comm", 0666, proc_dir, &eth_proc_ops);
	if(entry==NULL)
	{
		printk(KERN_ERR "Failed to create Ds3 control file (summary)!\n");
		return ;
	}

	handle_init();
}

void 
ethCardDbgLoadDefaultCfg(void)
{
	struct file *fp = NULL;
	int len;
	loff_t offset=0;
	char buf[512];
	int i=0;
	char cmd_line[64];
	int cmd_line_index;
#define DS3_CFG_FILE_PATH "/var/system/test_ds1.cfg"

	s_debug_cfg_exist=0;

	fp = filp_open(DS3_CFG_FILE_PATH, O_RDONLY, 0);
	if (IS_ERR(fp))
	{
		return ;
	}

	s_debug_cfg_exist=1;

	BRYANT_DEBUG("load default cfg at %s", DS3_CFG_FILE_PATH);

	memset(buf, 0x00, sizeof(buf));
	len=kernel_read(fp, buf, sizeof(buf), &offset);

	if(len<=0)
	{
		filp_close(fp, NULL); 
		return ;
	}

	memset(cmd_line, 0x00, sizeof(cmd_line));
	cmd_line_index=0;
	for(i=0; i<len; i++)
	{
		if(buf[i]=='\n')
		{
			char *cmd_str=NULL;
			char *end;
			int handler_index=0;

			cmd_str=ethCardDbgGetToken(cmd_line, &end);

			for(handler_index=0; handler_index < s_handler_len ; handler_index++)
			{
				if(strcmp(cmd_str, s_handle_arr[handler_index].map_str)==0)
				{
					BRYANT_DEBUG("cmd_line match:%s %s", cmd_line, end);
					s_handle_arr[handler_index].handler(handler_index, end);
				}
			}

			memset(cmd_line, 0x00, sizeof(cmd_line));
			cmd_line_index=0;
		}
		else 
		{
			if(buf[i]=='\r')
			{
				cmd_line[cmd_line_index]=' ';
			}
			else
			{
				cmd_line[cmd_line_index]=buf[i];
			}

			cmd_line_index++;
		}
	}

	filp_close(fp, NULL); 

	return ;
}


static ssize_t
eth_proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
{
	char kernel_buf[512];
	int cmd=0;
	char *cmd_str=NULL;
	char *arg=NULL;
	int i = 0;

	if(count<1 || count>=sizeof(kernel_buf))
		return(-EIO);

	if(copy_from_user(&kernel_buf, buffer, count))
		return(-EFAULT);


	kernel_buf[count]='\0';

	cmd_str=ethCardDbgGetToken(kernel_buf, &arg);

	cmd=str2dec(cmd_str);

	for(i=0; i < s_handler_len ; i++){
		if( (!ch_is_num(cmd_str[0]) && strcmp(cmd_str, s_handle_arr[i].map_str)==0) ||
			(ch_is_num(cmd_str[0]) && s_handle_arr[i].type==cmd))
		{
			s_handle_arr[i].handler(i, arg);
			return count;
		}
	}

	BRYANT_DEBUG("cmd_str:%s unknow", cmd_str);
	
	return (count);
}

static int
eth_proc_show(struct seq_file *m, void *v)
{
	int i = 0;

	for(i=0; i < s_handler_len ; i++)
	{
		if(s_handle_arr[i].handler==handler_save_cfg)
			seq_printf(m, "[%d] %s %s --%s (%d)\n", s_handle_arr[i].type, s_handle_arr[i].map_str,
			s_handle_arr[i].arg, s_handle_arr[i].helper, s_handle_arr[i].setup);
		else 
			seq_printf(m, "[%d] %s %s --%s\n", s_handle_arr[i].type, s_handle_arr[i].map_str,
			s_handle_arr[i].arg, s_handle_arr[i].helper);
	}

	seq_printf(m, "ver=%s\n","0001");
	
	return (0);
}

static int
eth_proc_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, eth_proc_show, PDE_DATA(inode));
}
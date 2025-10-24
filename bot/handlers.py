from aiogram import Router, F
from aiogram.types import Message, CallbackQuery
import asyncio
from datetime import datetime
import os
import logging

from config import STAT_FILE
from inline import main_menu, stats_menu

router = Router()

logger = logging.getLogger(__name__)

@router.message(F.text == "/start")
async def start_handler(message: Message):
    logger.info("Получена команда /start от %s", message.from_user.id)
    await message.answer("Добро пожаловать! Выберите опцию:", reply_markup=main_menu)

@router.callback_query(F.data == "stats")
async def stats_handler(query: CallbackQuery):
    logger.info("Пользователь %s запросил статистику", query.from_user.id)
    msg = await query.message.answer("Загрузка статистики...")
    asyncio.create_task(update_stats(query.bot, msg.chat.id, msg.message_id))
    await query.answer()

@router.callback_query(F.data == "back")
async def back_handler(query: CallbackQuery):
    logger.info("Пользователь %s вернулся в главное меню", query.from_user.id)
    try:
        await query.message.delete()
    except Exception as e:
        logger.error("Ошибка при удалении сообщения: %s", e)
    await query.answer()

@router.callback_query(F.data == "control")
async def control_handler(query: CallbackQuery):
    logger.info("Пользователь %s запросил управление устройствами", query.from_user.id)
    await query.message.answer("Управление устройствами (в разработке).")
    await query.answer()

async def update_stats(bot, chat_id, message_id):
    logger.info("Запущена задача обновления статистики для chat_id=%s, message_id=%s", chat_id, message_id)
    while True:
        stats_text = get_stats()
        text = f"Последнее обновление {datetime.now().strftime('%H:%M:%S')}:\n\n{stats_text}"
        try:
            await bot.edit_message_text(text=text, chat_id=str(chat_id), message_id=message_id, reply_markup=stats_menu)
            logger.debug("Сообщение статистики обновлено: %s", text)
        except Exception as e:
            logger.error("Ошибка при обновлении статистики (chat_id=%s, message_id=%s): %s", chat_id, message_id, e)
            break  
        await asyncio.sleep(5)

def get_stats():
    if not os.path.exists(STAT_FILE):
        logger.error("Файл статистики не найден: %s", STAT_FILE)
        return f"Файл статистики не найден: {STAT_FILE}"
    
    try:
        with open(STAT_FILE, 'r') as f:
            lines = f.readlines()
        logger.debug("Прочитан файл статистики: %d строк", len(lines))
    except PermissionError:
        logger.error("Нет прав доступа к файлу: %s", STAT_FILE)
        return f"Ошибка: Нет прав доступа к файлу {STAT_FILE}"
    except Exception as e:
        logger.error("Ошибка чтения файла %s: %s", STAT_FILE, e)
        return f"Ошибка чтения файла: {str(e)}"
    
    ts_temps = []
    lc_lights = []
    
    for line in lines:
        parts = line.strip().split()
        if len(parts) != 3:
            logger.warning("Некорректная строка в файле: %s", line.strip())
            continue
        typ, name, val = parts
        if typ == "TS":
            try:
                temp = float(val)
                ts_temps.append((name, temp))
                logger.debug("Обработан TS: %s, температура=%.1f", name, temp)
            except ValueError:
                logger.warning("Некорректное значение температуры в строке: %s", line.strip())
        elif typ == "LC":
            try:
                mask = int(val)
                if mask == -1:
                    on_count = 0  
                else:
                    on_count = bin(mask).count('1')
                total_lamps = 32  
                percent = (on_count / total_lamps) * 100 if total_lamps > 0 else 0
                lc_lights.append(f"{name}: {on_count} ламп включено ({percent:.1f}% от всех светильников)")
                logger.debug("Обработан LC: %s, маска=%d, включено=%d (%.1f%%)", name, mask, on_count, percent)
            except ValueError:
                logger.warning("Некорректное значение маски в строке: %s", line.strip())
    
    text = "Температура:\n"
    if ts_temps:
        temps = [t[1] for t in ts_temps]
        avg = sum(temps) / len(temps) if temps else 0
        for name, temp in ts_temps:
            text += f"{name}: {temp:.1f}°C\n"
        text += f"Средняя: {avg:.1f}°C\n\n"
    else:
        text += "Нет данных о температуре.\n\n"
        logger.info("Нет данных о температуре в файле")
    
    text += "Освещение:\n"
    if lc_lights:
        text += "\n".join(lc_lights) + "\n"
    else:
        text += "Нет данных об освещении.\n"
        logger.info("Нет данных об освещении в файле")
    
    return text